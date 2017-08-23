let Database = require('./Database')

// DATA MODEL
// supplierJSON = {
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

module.exports = class Supplier extends Database {
	constructor(env) {
		super('supplier', env)
	}

	//
	// Loads a single supplier from database and pass it to the callback function
	//
	findById(id, cb) {
		this.db.get(id, { revs_info: false}, (err, supplierBody) => {
			if (err) {
				return cb('Supplier findById: Error loading supplier with ID: ' + id + "\n" + err, null)
			}

			return cb(null, supplierBody)
		})
	}

	//
	// Loads a single supplier from the database by name and pass it to the callback function
	// WARNING: if multiple suppliers are found with the same name, only the first will be selected
	//
	findByName(name, cb) {
		this.db.view('supplier', 'by_name', {key: name}, (err, supplierByName) => {
			if (err) {
				console.error(err)
				return cb(err, null)
			}

			if (supplierByName.rows.length > 0) {
				return this.foundSupplier(supplierByName, name, cb)
			} else {
				return cb(null, null) // No supplier found
			}
		})
	}

	foundSupplier(body, name, cb) {
		var supplierList = []
		
		body.rows.forEach((supplier_doc) => {
			supplierList.push(supplier_doc.value)
		})

		if (supplierList.length === 0) {
			return cb (null, null) // No supplier found
		} 

		// Found multiple suppliers with same name
		if (supplierList.length > 1) {
			return cb('Found multiple suppliers with name: ' + name, null)
		}

		return cb(null, supplierList[0])
	}

	createSupplier(supplier, cb) {
		this.db.view('supplier', 'by_name', {key: supplier.name}, (err, body) => {
			if (err) {
				console.error("createSupplier: Error loading supplier with name: ", supplier.name, err)
				return cb(err, null)
			}

			if (body.rows.length !== 0) {
				console.error("createSupplier: Cannot create supplier since the name already exist: ", supplier.name)
				return cb(null, "WN") // Wrong Name --> WN
			}

			var supplierJSON = {
				name: supplier.name,
				priceList: supplier.priceList
			}

			this.db.insert(supplierJSON, (err2, body) => {
				if (err) {
					console.error("createSupplier: Failed to insert into supplier DB", err2)
					return cb(err, null)
				}
				console.log("createSupplier: Supplier created successfully: ", body)
				return cb(null, supplierJSON)
			})
		})
	}

	deleteSupplier(name, cb) {
		this.db.view('supplier', 'by_id', {key: id}, (err, body) => {
			if (err) {
				console.log("deleteSupplier: Error loading supplier with id: ", id, err)
				return cb(err, null)
			}

			if (body.rows.length === 0) {
				console.log("deleteSupplier: No suppliers found with the id: ", id)
				return cb('Supplier not found', null)
			}

			if (body.rows.length > 1) {
				console.log("deleteSupplier: Found multiple suppliers with the id: ", id)
				return cb('Multiple suppliers found', null)
			}

			this.db.destroy(id, rev, (err, body) => {
				if (err) {
					console.log('deleteSupplier: Failed to delete supplier', err)
					return cb(err, null)
				}
				console.log('deleteSupplier: Supplier deleted successfully: ', body)
				return cb(null, id)
			})
		})
	}

	editSupplierById(id, supplier, cb) {
		this.db.get(id, (err, oldSupplier) => {
			if (!oldSupplier) {
				return cb(null, { success: false, reason: 'Cannot found supplier', oldSupplier: null })
			}

			var newSupplier = {
				_id: 		oldSupplier._id,
				_rev: 		oldSupplier._rev,
				name: 		supplier.name,
				priceList: 	supplier.priceList
			}

			this.db.insert(newSupplier, (err, body) => {
				if (err) {
					console.error("editSupplierById insert supplierId: ", id, err)
					return cb(err, null)
				}
				return cb(null, { success: true, oldSupplier: oldSupplier, newSupplier: newSupplier })
			})
		})
	}

	getSuppliers(options, cb) {
		var opts = {
				name: 		options.name
			},
			result = []

		// Start from the narrowest query (smallest result) to the broadest view (largest result) before filtering by ther options
		if (opts.name) {
			this.db.view('supplier', 'by_name', {key: opts.username}, (err, body) => {
				if (err) {
					console.error('getSuppliers: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let supplier = body.rows[i].value

					result.push(supplier)
				}
				cb(null, result)
			})
		} else {
			this.db.view('supplier', 'by_id', (err, body) => {
				if (err) {
					console.error('getSuppliers: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let supplier = body.rows[i].value

					result.push(supplier)
				}
				cb(null, result)
			})
		}
	}

	getAllSuppliers(options, cb) {
		var opts = {
				name: 		options.name
			},
			result = []

		// Start from the narrowest query (smallest result) to the broadest view (largest result) before filtering by ther options
		if (opts.name) {
			this.db.view('supplier', 'by_name', (err, body) => {
				if (err) {
					console.error('getSuppliers: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let supplier = body.rows[i].value

					result.push(supplier)
				}
				cb(null, result)
			})
		} else {
			this.db.view('supplier', 'by_id', (err, body) => {
				if (err) {
					console.error('getSuppliers: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let supplier = body.rows[i].value

					result.push(supplier)
				}
				cb(null, result)
			})
		}
	}
}