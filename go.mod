module dnsleaf

go 1.25.3

require github.com/miekg/dns v1.1.62

require (
	github.com/gdamore/tcell/v3 v3.3.0
	github.com/x0rbyte/tview v0.0.0-20260102164552-b45d50115f5f
)

require (
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/gdamore/encoding v1.0.1 // indirect
	github.com/lucasb-eyer/go-colorful v1.4.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	golang.org/x/mod v0.34.0 // indirect
	golang.org/x/net v0.52.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/term v0.42.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	golang.org/x/tools v0.43.0 // indirect
)

replace github.com/miekg/dns => ../miekg-dns

replace github.com/x0rbyte/tview => ./third_party/x0rbyte-tview
