let Database = require('./Database')

// DATA MODEL
// itemJSON = {
// 	name: 'item name',
// 	quantity: '2'
// }

module.exports = class Item extends Database {
	constructor(env) {
		super('item', env)
	}

	//
	// Loads a single item from database by ID and pass it to the callback function
	//
	findById(id, cb) {
		this.db.get(id, { revs_info: false}, (err, itemBody) => {
			if (err) {
				return cb('Item findById: Error loading item with ID: ' + id + "\n" + err, null)
			}

			return cb(null, itemBody)
		})
	}

	//
	// Loads a single item from the database by name and pass it to the callback function
	// WARNING: if multiple items are found with the same name, only the first will be selected
	//
	findByName(name, cb) {
		this.db.view('item', 'by_name', {key: name}, (err, itemByName) => {
			if (err) {
				console.error(err)
				return cb(err, null)
			}

			if (itemByName.rows.length > 0) {
				return this.foundItem(itemByName, name, cb)
			} else {
				return cb(null, null) // No item found
			}
		})
	}

	foundItem(body, name, cb) {
		var itemList = []
		
		body.rows.forEach((item_doc) => {
			itemList.push(item_doc.value)
		})

		if (itemList.length === 0) {
			return cb (null, null) // No item found
		} 

		// Found multiple items with same name
		if (itemList.length > 1) {
			return cb('Found multiple items with name: ' + name, null)
		}

		return cb(null, itemList[0])
	}

	createItem(item, cb) {
		this.db.view('item', 'by_name', {key: item.name}, (err, body) => {
			if (err) {
				console.error("createItem: Error loading item with name: ", item.name, err)
				return cb(err, null)
			}

			if (body.rows.length !== 0) {
				console.error("createItem: Cannot create item since the name already exist: ", item.name)
				return cb(null, "WN") // Wrong Name --> WN
			}

			var itemJSON = {
				name: item.name,
				quantity: item.quantity
			}

			this.db.insert(itemJSON, (err2, body) => {
				if (err) {
					console.error("createItem: Failed to insert into item DB", err2)
					return cb(err, null)
				}
				console.log("createItem: Item created successfully: ", body)
				return cb(null, itemJSON)
			})
		})
	}

	deleteItem(id, rev, cb) {
		this.db.view('item', 'by_id', {key: id}, (err, body) => {
			if (err) {
				console.log("deleteItem: Error loading item with id: ", id, err)
				return cb(err, null)
			}

			if (body.rows.length === 0) {
				console.log("deleteItem: No items found with the id: ", id)
				return cb('Item not found', null)
			}

			if (body.rows.length > 1) {
				console.log("deleteItem: Found multiple items with the id: ", id)
				return cb('Multiple items found', null)
			}

			this.db.destroy(id, rev, (err, body) => {
				if (err) {
					console.log('deleteItem: Failed to delete item', err)
					return cb(err, null)
				}
				console.log('deleteItem: Item deleted successfully: ', body)
				return cb(null, id)
			})
		})
	}

	editItemById(id, item, cb) {
		this.db.get(id, (err, oldItem) => {
			if (!oldItem) {
				return cb(null, { success: false, reason: 'Cannot found item', oldItem: null })
			}

			var newItem = {
				_id: 		oldItem._id,
				_rev: 		oldItem._rev,
				name: 		item.name,
				quantity: 	item.quantity
			}

			this.db.insert(newItem, (err, body) => {
				if (err) {
					console.error("editItemByID insert itemID: ", id, err)
					return cb(err, null)
				}
				return cb(null, { success: true, oldItem: oldItem, newItem: newItem })
			})
		})
	}

	getItems(options, cb) {
		var opts = {
				name: 		options.name,
				quantity: 	options.quantity
			},
			result = []

		// Start from the narrowest query (smallest result) to the broadest view (largest result) before filtering by ther options
		if (opts.name) {
			this.db.view('item', 'by_name', {key: opts.username}, (err, body) => {
				if (err) {
					console.error('getItems: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let item = body.rows[i].value
					
					if (opts.quantity && opts.quantity !== item.quantity) {
						continue
					}

					result.push(item)
				}
				cb(null, result)
			})
		} else {
			this.db.view('item', 'by_id', (err, body) => {
				if (err) {
					console.error('getItems: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let item = body.rows[i].value

					result.push(item)
				}
				cb(null, result)
			})
		}
	}

	getAllItems(options, cb) {
		var opts = {
				name: 		options.name,
				quantity: 	options.quantity
			},
			result = []

		// Start from the narrowest query (smallest result) to the broadest view (largest result) before filtering by ther options
		if (opts.name) {
			this.db.view('item', 'by_name', (err, body) => {
				if (err) {
					console.error('getAllItems: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let item = body.rows[i].value
					
					if (opts.quantity && opts.quantity !== item.quantity) {
						continue
					}

					result.push(item)
				}
				cb(null, result)
			})
		} else {
			this.db.view('item', 'by_id', (err, body) => {
				if (err) {
					console.error('getAllItems: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let item = body.rows[i].value

					result.push(item)
				}
				cb(null, result)
			})
		}
	}
}