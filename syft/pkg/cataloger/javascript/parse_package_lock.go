package javascript

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/relationship"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// packageLock represents a JavaScript package.lock json file
type packageLock struct {
	Requires        bool `json:"requires"`
	LockfileVersion int  `json:"lockfileVersion"`
	Dependencies    map[string]lockDependency
	Packages        map[string]lockPackage
}

// lockDependency represents a single package dependency listed in the package.lock json file
type lockDependency struct {
	Version      string                    `json:"version"`
	Resolved     string                    `json:"resolved"`
	Integrity    string                    `json:"integrity"`
	Dev          bool                      `json:"dev"`
	Dependencies map[string]lockDependency `json:"dependencies"`
}

type lockPackage struct {
	Name         string             `json:"name"` // only present in the root package entry (named "")
	Version      string             `json:"version"`
	Resolved     string             `json:"resolved"`
	Integrity    string             `json:"integrity"`
	License      packageLockLicense `json:"license"`
	Dev          bool               `json:"dev"`
	Link         bool               `json:"link"`
	Dependencies map[string]string  `json:"dependencies"`
}

// packageLockLicense
type packageLockLicense []string

type genericPackageLockAdapter struct {
	cfg             CatalogerConfig
	licenseResolver javascriptLicenseResolver
}

func newGenericPackageLockAdapter(cfg CatalogerConfig) genericPackageLockAdapter {
	return genericPackageLockAdapter{
		cfg:             cfg,
		licenseResolver: newJavascriptLicenseResolver(cfg),
	}
}

// parsePackageLock parses a package-lock.json and returns the discovered JavaScript packages.
func (a genericPackageLockAdapter) parsePackageLock(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	// in the case we find package-lock.json files in the node_modules directories, skip those
	// as the whole purpose of the lock file is for the specific dependencies of the root project
	if pathContainsNodeModulesDirectory(reader.LocalPath()) {
		return nil, nil, nil
	}

	var pkgs []pkg.Package
	var relationships []artifact.Relationship
	dec := json.NewDecoder(reader)

	var lock packageLock
	for {
		if err := dec.Decode(&lock); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to parse package-lock.json file: %w", err)
		}
	}

	if lock.LockfileVersion == 1 {
		pkgs = append(pkgs, a.packageLockV1Packages(ctx, resolver, reader.Location, lock.Dependencies)...)
	}

	if lock.LockfileVersion == 2 || lock.LockfileVersion == 3 {
		packagesByPath := make(map[string]pkg.Package, len(lock.Packages))
		for installPath, pkgMeta := range lock.Packages {
			if installPath == "" && pkgMeta.Name == "" {
				continue
			}
			name := installPath

			// skip packages that are only present as a dev dependency
			if !a.cfg.IncludeDevDependencies && pkgMeta.Dev {
				continue
			}

			// handles alias names
			if pkgMeta.Name != "" {
				name = pkgMeta.Name
			}

			newPkg := newPackageLockV2Package(ctx, a.licenseResolver, resolver, reader.Location, getNameFromPath(name), pkgMeta)
			pkgs = append(pkgs, newPkg)
			packagesByPath[installPath] = newPkg
		}
		relationships = packageLockRelationships(lock.Packages, packagesByPath)
	}

	pkg.Sort(pkgs)

	return pkgs, relationships, unknown.IfEmptyf(pkgs, "unable to determine packages")
}

// npm resolves a request against the nearest installed package with that name.
// Aliases use their installed name in the lockfile paths.
func packageLockRelationships(entries map[string]lockPackage, packagesByPath map[string]pkg.Package) []artifact.Relationship {
	var relationships []artifact.Relationship
	seen := make(map[[2]artifact.ID]bool)
	for installPath, parent := range packagesByPath {
		for name := range entries[installPath].Dependencies {
			childPath, ok := packageLockDependencyPath(entries, installPath, name)
			if !ok {
				continue
			}
			if entry := entries[childPath]; entry.Link {
				childPath = path.Clean(entry.Resolved)
			}
			child, ok := packagesByPath[childPath]
			if !ok {
				continue
			}
			key := [2]artifact.ID{child.ID(), parent.ID()}
			if !seen[key] {
				seen[key] = true
				relationships = append(relationships, artifact.Relationship{From: child, To: parent, Type: artifact.DependencyOfRelationship})
			}
		}
	}
	relationship.Sort(relationships)
	return relationships
}

func packageLockDependencyPath(entries map[string]lockPackage, installPath, name string) (string, bool) {
	for directory := path.Clean(installPath); ; directory = path.Dir(directory) {
		if path.Base(directory) != "node_modules" {
			candidate := path.Join(directory, "node_modules", name)
			if _, ok := entries[candidate]; ok {
				return candidate, true
			}
		}
		if directory == "." || directory == "/" {
			return "", false
		}
	}
}

func (a genericPackageLockAdapter) packageLockV1Packages(ctx context.Context, resolver file.Resolver, location file.Location, dependencies map[string]lockDependency) []pkg.Package {
	var pkgs []pkg.Package
	seen := make(map[string]struct{})

	var walk func(map[string]lockDependency)
	walk = func(dependencies map[string]lockDependency) {
		for name, pkgMeta := range dependencies {
			// Skipping a dev-only dependency also skips its dev-only subtree.
			if !a.cfg.IncludeDevDependencies && pkgMeta.Dev {
				continue
			}

			p := newPackageLockV1Package(ctx, a.licenseResolver, resolver, location, name, pkgMeta)
			if _, exists := seen[p.PURL]; !exists {
				pkgs = append(pkgs, p)
				seen[p.PURL] = struct{}{}
			}

			walk(pkgMeta.Dependencies)
		}
	}

	walk(dependencies)
	return pkgs
}

func (licenses *packageLockLicense) UnmarshalJSON(data []byte) (err error) {
	// The license field could be either a string or an array.

	// 1. An array
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*licenses = arr
		return nil
	}

	// 2. A string
	var str string
	if err = json.Unmarshal(data, &str); err == nil {
		*licenses = make([]string, 1)
		(*licenses)[0] = str
		return nil
	}

	// debug the content we did not expect
	if len(data) > 0 {
		log.WithFields("license", string(data)).Debug("Unable to parse the following `license` value in package-lock.json")
	}

	// 3. Unexpected
	// In case we are unable to parse the license field,
	// i.e if we have not covered the full specification,
	// we do not want to throw an error, instead assign nil.
	return nil
}

func getNameFromPath(path string) string {
	parts := strings.Split(path, "node_modules/")
	return parts[len(parts)-1]
}
