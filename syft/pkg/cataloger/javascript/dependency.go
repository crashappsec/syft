package javascript

import (
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

func pnpmLockDependencySpecifier(p pkg.Package) dependency.Specification {
	meta, ok := p.Metadata.(pkg.PnpmLockEntry)
	if !ok {
		log.Tracef("cataloger failed to extract pnpm lock metadata for package %+v", p.Name)
		return dependency.Specification{}
	}

	provides := []string{p.Name}

	var requires []string

	for name := range meta.Dependencies {
		requires = append(requires, name)
	}
	return dependency.Specification{
		ProvidesRequires: dependency.ProvidesRequires{
			Provides: provides,
			Requires: requires,
		},
	}
}

func bunLockDependencySpecifier(p pkg.Package) dependency.Specification {
	meta, ok := p.Metadata.(pkg.BunLockEntry)
	if !ok {
		log.Tracef("cataloger failed to extract bun lock metadata for package %+v", p.Name)
		return dependency.Specification{}
	}

	provides := []string{p.Name}

	var requires []string

	for name := range meta.Dependencies {
		requires = append(requires, name)
	}
	for name := range meta.OptionalDependencies {
		requires = append(requires, name)
	}
	return dependency.Specification{
		ProvidesRequires: dependency.ProvidesRequires{
			Provides: provides,
			Requires: requires,
		},
	}
}
