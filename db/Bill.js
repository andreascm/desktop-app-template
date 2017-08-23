let Database = require('./Database')

// DATA MODEL
// billJSON = {
// 	storeId: 	'store_id',
// 	date: 		'6/6/2017',
// 	totalPrice: '23541.8',
// 	itemList: 	[
// 		{
// 			itemId: 	'item_id',
// 			quantity: 	'2',
// 			price: 		'11.5'
// 		},
// 		{
// 			itemId: 	'item_id_2',
// 			quantity: 	'5',
// 			price: 		'9.3'
// 		},
// 		...
// 	],
// 	buy: 		'false'
// }

module.exports = class Bill extends Database {
	constructor(env) {
		super('bill', env)
	}

	//
	// Loads a single bill from database by ID and pass it to the callback function
	//
	findById(id, cb) {
		this.db.get(id, { revs_info: false }, (err, billBody) => {
			if (err) {
				return cb('Bill findById: Error loading bill with ID: ' + id + "\n" + err, null)
			}

			return cb(null, billBody)
		})
	}

	//
	// Loads bills from the database by date and pass it to the callback function
	//
	findByDate(date, cb) {
		this.db.view('bill', 'by_date', {key: date}, (err, billByDate) => {
			if (err) {
				console.error(err)
				return cb(err, null)
			}

			if (billByDate.rows.length > 0) {
				return this.foundBills(billByDate, date, cb)
			} else {
				return cb(null, null) // No bill found
			}
		})
	}

	//
	// Loads bills from the database by store id and pass it to the callback function
	//
	findByStoreId(storeId, cb) {
		this.db.view('bill', 'by_store_id', {key: storeId}, (err, billByStoreId) => {
			if (err) {
				console.error(err)
				return cb(err, null)
			}

			if (billByStoreId.rows.length > 0) {
				return this.foundBills(billByStoreId, cb)
			} else {
				return cb(null, null) // No bill found
			}
		})
	}

	foundBills(body, cb) {
		var billList = []
		
		body.rows.forEach((bill_doc) => {
			billList.push(bill_doc.value)
		})

		if (billList.length === 0) {
			return cb (null, null) // No bill found
		}

		return cb(null, billList)
	}

	createBill(bill, cb) {
		var billJSON = {
			storeId: 	bill.storeId,
			date: 		bill.date,
			totalPrice: bill.totalPrice,
			itemList: 	bill.itemList,
			buy: 		bill.buy
		}

		this.db.insert(billJSON, (err, body) => {
			if (err) {
				console.error("createBill: Failed to insert into bill DB", err)
				return cb(err, null)
			}
			console.log("createBill: Bill created successfully: ", body)
			return cb(null, billJSON)
		})
	}

	deleteBill(id, rev, cb) {
		this.db.view('bill', 'by_id', {key: id}, (err, body) => {
			if (err) {
				console.log("deleteBill: Error loading bill with id: ", id, err)
				return cb(err, null)
			}

			if (body.rows.length === 0) {
				console.log("deleteBill: No bills found with the id: ", id)
				return cb('Bill not found', null)
			}

			if (body.rows.length > 1) {
				console.log("deleteBill: Found multiple bills with the id: ", id)
				return cb('Multiple bills found', null)
			}

			this.db.destroy(id, rev, (err, body) => {
				if (err) {
					console.log('deleteBill: Failed to delete bill', err)
					return cb(err, null)
				}
				console.log('deleteBill: Bill deleted successfully: ', body)
				return cb(null, id)
			})
		})
	}

	editBillById(id, bill, cb) {
		this.db.get(id, (err, oldBill) => {
			if (!oldBill) {
				return cb(null, { success: false, reason: 'Cannot found bill', oldBill: null })
			}

			var newBill = {
				_id: 		oldBill._id,
				_rev: 		oldBill._rev,
				storeId: 	bill.storeId,
				date: 		bill.date,
				totalPrice: bill.totalPrice,
				itemList: 	bill.itemList,
				buy: 		bill.buy
			}

			this.db.insert(newBill, (err, body) => {
				if (err) {
					console.error("editBillByID insert billID: ", id, err)
					return cb(err, null)
				}
				return cb(null, { success: true, oldBill: oldBill, newBill: newBill })
			})
		})
	}

	getBills(options, cb) {
		var opts = {
				storeId: 	options.storeId,
				date: 		options.date,
				buy: 		options.buy
			},
			result = []

		// Start from the narrowest query (smallest result) to the broadest view (largest result) before filtering by ther options
		if (opts.date) {
			this.db.view('bill', 'by_date', {key: opts.date}, (err, body) => {
				if (err) {
					console.error('getBills: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let bill = body.rows[i].value
					result.push(bill)
				}
				cb(null, result)
			})
		} else if (opts.storeId) {
			this.db.view('bill', 'by_store_id', {key: opts.storeId}, (err, body) => {
				if (err) {
					console.error('getBills: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let bill = body.rows[i].value
					result.push(bill)
				}
				cb(null, result)
			})
		} else if (opts.buy) {
			this.db.view('bill, by_type', {key: opts.buy}, (err, body) => {
				if (err) {
					console.error('getBills: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let bill = body.rows[i].value
					result.push(bill)
				}
				cb(null, result)
			})
		} else {
			this.db.view('bill', 'by_id', (err, body) => {
				if (err) {
					console.error('getBills: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let bill = body.rows[i].value
					result.push(bill)
				}
				cb(null, result)
			})
		}
	}

	getAllBills(options, cb) {
		var result = []

		// Start from the narrowest query (smallest result) to the broadest view (largest result) before filtering by ther options
		if (options === 'date') {
			this.db.view('bill', 'by_date', (err, body) => {
				if (err) {
					console.error('getBills: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let bill = body.rows[i].value
					result.push(bill)
				}
				cb(null, result)
			})
		} else if (options === 'store') {
			this.db.view('bill', 'by_store_id', (err, body) => {
				if (err) {
					console.error('getBills: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let bill = body.rows[i].value
					result.push(bill)
				}
				cb(null, result)
			})
		} else if (options === 'type') {
			this.db.view('bill', 'by_type', (err, body) => {
				if (err) {
					console.error('getBills: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let bill = body.rows[i].value
					result.push(bill)
				}
				cb(null, result)
			})
		} else {
			this.db.view('bill', 'by_id', (err, body) => {
				if (err) {
					console.error('getBills: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let bill = body.rows[i].value
					result.push(bill)
				}
				cb(null, result)
			})
		}
	}
}