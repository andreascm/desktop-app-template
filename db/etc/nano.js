var net = require('net')

module.exports = (() => {
	findLocalPublicAddress = () => {
		var os = require('os'),
			interfaces = os.networkInterfaces(),
			addresses = []

		for (var k in interfaces) {
			for (var k2 in interfaces[k]) {
				var address = interfaces[k][k2]
				if (address.family === 'IPv4' && !address.internal) {
					addresses.push(address.address)
				}
			}
		}

		if (!addresses[0]) {
			// If there's no addresses, the user is probably disconnected. Default to localhost
			addresses[0] = "127.0.0.1";
			console.log("[db] System is offline - fall back CouchDB address: ", addresses[0])
		} else {
			// If there's more than 1 public facing IP Address, just use the first one
			console.log("[db] Selected Local CouchDB address:", addresses[0])
		}

		return addresses[0]
	}

	var addr, port = '5984'

	switch(process.env.NODE_ENV) {
		case 'production':
			addr = 'app.garuda.io'
			console.log("[db] Production CouchDB hostname:", addr)
			break
		case 'staging':
			addr = 'one.garuda.io'
			console.log("[db] Staging CouchDB hostname:", addr)
			break
		case 'development':
		default:
			if (process.env.DB_HOSTNAME) {
				addr = process.env.DB_HOSTNAME
				console.log("[db] Custom CouchDB hostname:", addr)
			} else {
				addr = '127.0.0.1'
				console.log("[db] Default Development CouchDB hostname:", addr)
			}
	}

	return require('nano')('http://' + addr + ':' + port)
})()