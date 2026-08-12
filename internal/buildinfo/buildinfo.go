package buildinfo

// Version and Commit are set at build time with -ldflags.
var (
	Version = "dev"
	Commit  = "unknown"
)
