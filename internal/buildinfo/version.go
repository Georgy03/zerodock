// Package buildinfo contains identity assigned when the scanner binary is
// built. Release builds override Version with -ldflags; keeping it in a small
// package gives the linker a stable symbol independent of cmd/scanner details.
package buildinfo

// Version is "dev" unless a release build supplies a Git tag such as v0.1.0.
// It is included in the attested-content hash, so an API cannot substitute a
// different release tag without invalidating the hardware-backed report.
var Version = "dev"
