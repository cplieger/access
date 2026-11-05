package blocklist

//go:generate go run ../cmd/genblocklist

// SeclistsCommit is the SecLists commit common.txt was generated from; go
// generate fetches the password lists at it.
// renovate: datasource=git-refs depName=seclists packageName=https://github.com/danielmiessler/SecLists branch=master
const SeclistsCommit = "f1196104c5594a19d78b486c52c0794b9d947993"
