//
// Base class for all database interactions
//

let nano = null // Singleton nano used to connect to database

module.exports = class Database {
	constructor(dbName, environment = process.env.NODE_ENV) {
		if (!nano) {
			let address, port = '5984'

			switch(environment) {
				case 'production':
					// address = ''
					// console.log("[DB] Production CouchDB hostname:", address)
					// break
				case 'staging':
					// address = ''
					// console.log("[DB] Staging CouchDB hostname:", address)
					// break
				case 'development':
				default:
					if (process.env.DB_HOSTNAME) {
						address = process.env.DB_HOSTNAME
						console.log("[DB] Custom CouchDB hostname:", address)
					} else {
						address = '127.0.0.1'
						console.log("[DB] Default Development CouchDB hostname:", address)
					}
			}
			nano = require('nano')('http://' + address + ':' + port)
		}

		this.dbName = dbName
		this.db = nano.use(dbName)
	}

	//
	// Always indicate success or failure
	//
	success(object, cb) {
		object.success = true
		return cb(null, object)
	}
	fail(reason, cb) {
		return cb(null, {
			success: false,
			reason: reason
		})
	}
	invalid(key, reason) {
		return {
			valid: false,
			invalid_key: key,
			reason: reason
		}
	}

	//
	// Common pattern to process view results
	// (options is optional)
	//
	// Valid options:
	//   - includeDeleted: true Set if you want to leave the deleted items intact
	//                          Otherwise, all results will filter objects with "deleted: true"
	//
	viewResultHandler(err, viewResult, options, cb) {
		if (err) {
			console.error(err)
			return cb(err, null)
		}
		if (viewResult.total_rows === 0)
			return cb(null, viewResult.rows) // []

		let opts, result

		if (typeof options === 'function') {
			cb = options
			opts = {}
		} else if (typeof options === 'object') {
			opts = options
		} else {
			opts = {}
		}

		if (opts.includeDeleted) {
			result = viewResult.rows.map(r => r.value)
		} else {
			result = _flattenAndFilterDeleted(viewResult.rows)
		}
		// other future options

		return cb(null, result)
	}
}

//
// "Private" methods defined outside the exported class
//
function _flattenAndFilterDeleted(array) {
	var result = []
	for (var i = 0; i < array.length; i++) {
		var object = array[i] && array[i].value ? array[i].value : {}
		if (!object.deleted)
			result.push(object)
	}
	return result
}