let Database = require('./Database')

// DATA MODEL
// storeJSON = {
// 	name: 'item name',
// 	priceList: [
// 		{
// 			itemId: 'item_id',
// 			price: 	'11.5'
// 		},
// 		{
// 			itemId: 'item_id_2',
// 			price: 	'9.3'
// 		},
// 		...
// 	]
// }

module.exports = class Store extends Database {
	constructor(env) {
		super('store', env)
	}

	//
	// Loads a single store from database and pass it to the callback function
	//
	findById(id, cb) {
		this.db.get(id, { revs_info: false}, (err, storeBody) => {
			if (err) {
				return cb('Store findById: Error loading store with ID: ' + id + "\n" + err, null)
			}

			return cb(null, storeBody)
		})
	}

	//
	// Loads a single store from the database by name and pass it to the callback function
	// WARNING: if multiple stores are found with the same name, only the first will be selected
	//
	findByName(name, cb) {
		this.db.view('store', 'by_name', {key: name}, (err, storeByName) => {
			if (err) {
				console.error(err)
				return cb(err, null)
			}

			if (storeByName.rows.length > 0) {
				return this.foundStore(storeByName, name, cb)
			} else {
				return cb(null, null) // No store found
			}
		})
	}

	foundStore(body, name, cb) {
		var storeList = []
		
		body.rows.forEach((store_doc) => {
			storeList.push(store_doc.value)
		})

		if (storeList.length === 0) {
			return cb (null, null) // No store found
		} 

		// Found multiple stores with same name
		if (storeList.length > 1) {
			return cb('Found multiple stores with name: ' + name, null)
		}

		return cb(null, storeList[0])
	}

	createStore(store, cb) {
		this.db.view('store', 'by_name', {key: store.name}, (err, body) => {
			if (err) {
				console.error("createStore: Error loading store with name: ", store.name, err)
				return cb(err, null)
			}

			if (body.rows.length !== 0) {
				console.error("createStore: Cannot create store since the name already exist: ", store.name)
				return cb(null, "WN") // Wrong Name --> WN
			}

			var storeJSON = {
				name: store.name,
				priceList: store.priceList
			}

			this.db.insert(storeJSON, (err2, body) => {
				if (err) {
					console.error("createStore: Failed to insert into store DB", err2)
					return cb(err, null)
				}
				console.log("createStore: Store created successfully: ", body)
				return cb(null, storeJSON)
			})
		})
	}

	deleteStore(name, cb) {
		this.db.view('store', 'by_id', {key: id}, (err, body) => {
			if (err) {
				console.log("deleteStore: Error loading store with id: ", id, err)
				return cb(err, null)
			}

			if (body.rows.length === 0) {
				console.log("deleteStore: No stores found with the id: ", id)
				return cb('Store not found', null)
			}

			if (body.rows.length > 1) {
				console.log("deleteStore: Found multiple stores with the id: ", id)
				return cb('Multiple stores found', null)
			}

			this.db.destroy(id, rev, (err, body) => {
				if (err) {
					console.log('deleteStore: Failed to delete store', err)
					return cb(err, null)
				}
				console.log('deleteStore: Store deleted successfully: ', body)
				return cb(null, id)
			})
		})
	}

	editStoreById(id, store, cb) {
		this.db.get(id, (err, oldStore) => {
			if (!oldStore) {
				return cb(null, { success: false, reason: 'Cannot found store', oldStore: null })
			}

			var newStore = {
				_id: 		oldStore._id,
				_rev: 		oldStore._rev,
				name: 		store.name,
				priceList: 	store.priceList
			}

			this.db.insert(newStore, (err, body) => {
				if (err) {
					console.error("editStoreByID insert storeID: ", id, err)
					return cb(err, null)
				}
				return cb(null, { success: true, oldStore: oldStore, newStore: newStore })
			})
		})
	}

	getStores(options, cb) {
		var opts = {
				name: 		options.name
			},
			result = []

		// Start from the narrowest query (smallest result) to the broadest view (largest result) before filtering by ther options
		if (opts.name) {
			this.db.view('store', 'by_name', {key: opts.username}, (err, body) => {
				if (err) {
					console.error('getStores: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let store = body.rows[i].value

					result.push(store)
				}
				cb(null, result)
			})
		} else {
			this.db.view('store', 'by_id', (err, body) => {
				if (err) {
					console.error('getStores: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let store = body.rows[i].value

					result.push(store)
				}
				cb(null, result)
			})
		}
	}

	getAllStores(options, cb) {
		var opts = {
				name: 		options.name
			},
			result = []

		// Start from the narrowest query (smallest result) to the broadest view (largest result) before filtering by ther options
		if (opts.name) {
			this.db.view('store', 'by_name', (err, body) => {
				if (err) {
					console.error('getStores: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let store = body.rows[i].value

					result.push(store)
				}
				cb(null, result)
			})
		} else {
			this.db.view('store', 'by_id', (err, body) => {
				if (err) {
					console.error('getStores: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let store = body.rows[i].value

					result.push(store)
				}
				cb(null, result)
			})
		}
	}
}