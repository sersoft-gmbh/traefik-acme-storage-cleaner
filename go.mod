module github.com/sersoft-gmbh/traefik-acme-storage-cleaner

go 1.24.12

require github.com/traefik/traefik/v3 v3.6.7 // indirect

// Containous forks
replace (
	github.com/abbot/go-http-auth => github.com/containous/go-http-auth v0.4.1-0.20200324110947-a37a7636d23e
	github.com/mailgun/minheap => github.com/containous/minheap v0.0.0-20190809180810-6e71eb837595
)
