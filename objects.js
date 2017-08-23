//
// Transitional wrapper for API service design
// - currently served via the same origin
// - to move towards being served via api origin

var db = require('./db')

//
// STANDARD API RESPONSES
//
// Either success, fail, or error.
//
var error = {

	// Standard JSON response
	error : function(res, http_status_code, message) {
		if (!res) throw new Error('Response object required');
		if (!http_status_code) http_status_code = 520;
		if (!message) message = "Unknown Error";
		res.status(http_status_code).json({
			"error"   : http_status_code,
			"message" : message
		});
	},

	// Use these functions for clarity
	BadRequest          : function(res, msg) { this.error(res, 400, msg ? msg : 'Bad Request') },
	Unauthorized        : function(res, msg) { this.error(res, 401, msg ? msg : 'Unauthorized') },
	Forbidden           : function(res, msg) { this.error(res, 403, msg ? msg : 'Forbidden') },
	NotFound            : function(res, msg) { this.error(res, 404, msg ? msg : 'Not Found') },
	InternalServerError : function(res, msg) { this.error(res, 500, msg ? msg : 'Internal Server Error') }
}

var success = (res, json) => {
	if (typeof json !== 'object') json = {}
	json.success = true
	res.json(json)
}

var fail = (res, reason, json) => {
	if (typeof json !== 'object') json = {}
	if (typeof reason !== 'string') reason = reason.toString()
	json.success = false
	json.reason = reason
	res.json(json)
}

module.exports = (app, server, log) => {
	app.post('/api/create_item', (req, res) => {
		let item = {
			name: 		req.body.name,
			quantity: 	req.body.quantity
		}

		// TODO: validate all inputs, return BadRequest if inputs no good

		db.items.createItem(item, (itemErr, itemResult) => {
			if (itemErr) {
				log.info('create_item error createItem: ', itemErr)
				return error.InternalServerError(res)
			}

			if (itemResult === 'WN') {
				return fail(res, 'Name taken, try another one')
			}

			return success(res, itemResult)
		})
	})

	app.get('/api/all_item', (req, res) => {
		db.items.getAllItems({}, (itemErr, itemResult) => {
			if (itemErr) {
				return error.InternalServerError(res)
			} else {
				return success(res, itemResult)
			}
		})
	})

	app.get('/api/item_by_name', (req, res) => {
		var name = req.query.name
		db.items.getItems({name: name}, (itemErr, itemResult) => {
			if (itemErr) {
				return error.InternalServerError(res)
			} else {
				return success(res, itemResult)
			}
		})
	})

	app.get('/api/item_by_quantity', (req, res) => {
		var quantity = req.query.quantity
		db.items.getItems({quantity: quantity}, (itemErr, itemResult) => {
			if (itemErr) {
				return error.InternalServerError(res)
			} else {
				return success(res, itemResult)
			}
		})
	})

	app.post('/api/edit_item', (req, res) => {
		let itemId 	= req.body.itemId,
			item 	= req.body.item

		if (!itemId) {
			return error.BadRequest(res, 'itemId required')
		}

		if (typeof item !== 'object') {
			return error.BadRequest(res, 'item should be an obejct')
		}

		db.items.editItemById(itemId, item, (itemErr, itemResult) => {
			if (itemErr) {
				return error.InternalServerError(res)
			}

			if (!itemResult.success) {
				return fail(res, itemResult.reason)
			}

			return success(res, itemResult.newItem)
		})
	})

	app.post('/api/delete_item', (req, res) => {
		var id = req.body.id
			rev = req.body.rev

		db.items.deleteItem(id, rev, (itemErr, itemResult) => {
			if (itemErr) {
				return error.InternalServerError(res)
			}

			log.debug('delete_item successful: ', itemResult)
			return success(res)
		})
	})

	app.post('/api/create_store', (req, res) => {
		let store = {
			name: 		req.body.name,
			priceList: 	req.body.priceList
		}

		// TODO: validate all inputs, return BadRequest if inputs no good

		db.stores.createStore(store, (storeErr, storeResult) => {
			if (storeErr) {
				log.info('create_store error createStore: ', storeErr)
				return error.InternalServerError(res)
			}

			if (storeResult === 'WN') {
				return fail(res, 'Name taken, try another one')
			}

			return success(res, storeResult)
		})
	})

	app.get('/api/all_store', (req, res) => {
		db.stores.getAllStores({}, (storeErr, storeResult) => {
			if (storeErr) {
				return error.InternalServerError(res)
			} else {
				return success(res, storeResult)
			}
		})
	})

	app.get('/api/store_by_name', (req, res) => {
		var name = req.query.name
		db.stores.getStores({name: name}, (storeErr, storeResult) => {
			if (storeErr) {
				return error.InternalServerError(res)
			} else {
				return success(res, storeResult)
			}
		})
	})

	app.post('/api/edit_store', (req, res) => {
		let storeId = req.body.storeId,
			store 	= req.body.store

		if (!storeId) {
			return error.BadRequest(res, 'storeId required')
		}

		if (typeof store !== 'object') {
			return error.BadRequest(res, 'store should be an obejct')
		}

		db.stores.editStoreById(storeId, store, (storeErr, storeResult) => {
			if (storeErr) {
				return error.InternalServerError(res)
			}

			if (!storeResult.success) {
				return fail(res, storeResult.reason)
			}

			return success(res, storeResult.newStore)
		})
	})

	app.post('/api/delete_store', (req, res) => {
		var id = req.body.id,
			rev = req.body.rev

		db.stores.deleteStore(id, rev, (storeErr, storeResult) => {
			if (storeErr) {
				return error.InternalServerError(res)
			}

			log.debug('delete_store successful: ', storeResult)
			return success(res)
		})
	})

	app.post('/api/create_supplier', (req, res) => {
		let supplier = {
			name: 		req.body.name,
			priceList: 	req.body.priceList
		}

		// TODO: validate all inputs, return BadRequest if inputs no good

		db.suppliers.createSupplier(supplier, (supplierErr, supplierResult) => {
			if (supplierErr) {
				log.info('create_supplier error createSupplier: ', supplierErr)
				return error.InternalServerError(res)
			}

			if (supplierResult === 'WN') {
				return fail(res, 'Name taken, try another one')
			}

			return success(res, supplierResult)
		})
	})

	app.get('/api/all_supplier', (req, res) => {
		db.suppliers.getAllSuppliers({}, (supplierErr, supplierResult) => {
			if (supplierErr) {
				return error.InternalServerError(res)
			} else {
				return success(res, supplierResult)
			}
		})
	})

	app.get('/api/supplier_by_name', (req, res) => {
		var name = req.query.name
		db.suppliers.getSuppliers({name: name}, (supplierErr, supplierResult) => {
			if (supplierErr) {
				return error.InternalServerError(res)
			} else {
				return success(res, supplierResult)
			}
		})
	})

	app.post('/api/edit_supplier', (req, res) => {
		let supplierId = req.body.supplierId,
			supplier 	= req.body.supplier

		if (!supplierId) {
			return error.BadRequest(res, 'supplierId required')
		}

		if (typeof supplier !== 'object') {
			return error.BadRequest(res, 'supplier should be an obejct')
		}

		db.suppliers.editSupplierById(supplierId, supplier, (supplierErr, supplierResult) => {
			if (supplierErr) {
				return error.InternalServerError(res)
			}

			if (!supplierResult.success) {
				return fail(res, supplierResult.reason)
			}

			return success(res, supplierResult.newSupplier)
		})
	})

	app.post('/api/delete_supplier', (req, res) => {
		var id = req.body.id,
			rev = req.body.rev

		db.suppliers.deleteSupplier(id, rev, (supplierErr, supplierResult) => {
			if (supplierErr) {
				return error.InternalServerError(res)
			}

			log.debug('delete_supplier successful: ', supplierResult)
			return success(res)
		})
	})

	app.post('/api/create_bill', (req,res) => {
		let bill = {
			storeId: 	req.body.storeId,
			date: 		req.body.date,
			totalPrice: req.body.totalPrice,
			itemList: 	req.body.itemList,
			buy: 		req.body.buy
		}

		// TODO: validate all inputs, return BadRequest if inputs no good

		db.bills.createBill(bill, (billErr, billResult) => {
			if (billErr) {
				log.info('create_bill error createBill: ', billErr)
				return error.InternalServerError(res)
			}

			return success(res, billResult)
		})
	})

	app.get('/api/all_bill', (req, res) => {
		db.bills.getAllBills({}, (billErr, billResult) => {
			if (billErr) {
				return error.InternalServerError(res)
			} else {
				return success(res, billResult)
			}
		})
	})

	app.get('/api/all_bill_by_date', (req, res) => {
		db.bills.getAllBills('date', (billErr, billResult) => {
			if (billErr) {
				return error.InternalServerError(res)
			} else {
				return success(res, billResult)
			}
		})
	})

	app.get('/api/all_bill_by_type', (req, res) => {
		db.bills.getAllBills('type', (billErr, billResult) => {
			if (billErr) {
				return error.InternalServerError(res)
			} else {
				return success(res, billResult)
			}
		})
	})

	app.get('/api/all_bill_by_store', (req, res) => {
		db.bills.getAllBills('store', (billErr, billResult) => {
			if (billErr) {
				return error.InternalServerError(res)
			} else {
				return success(res, billResult)
			}
		})
	})

	app.get('/api/bill_by_date', (req, res) => {
		var date = req.query.date
		db.bills.getBills({date: date}, (billErr, billResult) => {
			if (billErr) {
				return error.InternalServerError(res)
			} else {
				return success(res, billResult)
			}
		})
	})

	app.get('/api/bill_by_store_id', (req, res) => {
		var storeId = req.query.storeId
		db.bills.getBills({storeId: storeId}, (billErr, billResult) => {
			if (billErr) {
				return error.InternalServerError(res)
			} else {
				return success(res, billResult)
			}
		})
	})

	app.post('/api/edit_bill', (req, res) => {
		let billId = req.body.billId,
			bill 	= req.body.bill

		if (!billId) {
			return error.BadRequest(res, 'billId required')
		}

		if (typeof bill !== 'object') {
			return error.BadRequest(res, 'bill should be an obejct')
		}

		db.bills.editBillById(billId, bill, (billErr, billResult) => {
			if (billErr) {
				return error.InternalServerError(res)
			}

			if (!billResult.success) {
				return fail(res, billResult.reason)
			}

			return success(res, billResult.newBill)
		})
	})

	app.post('/api/delete_bill', (req, res) => {
		var id = req.body.id,
			rev = req.body.rev

		db.bills.deleteBill(id, rev, (billErr, billResult) => {
			if (billErr) {
				return error.InternalServerError(res)
			}

			log.debug('delete_bill successful: ', billResult)
			return success(res)
		})
	})

	app.post('/api/create_stock', (req, res) => {
		let stock = {
			monthYear: 		req.body.monthYear,
			initialStock: 	req.body.initialStock,
			endStock: 		req.body.endStock,
			income: 		req.body.income,
			expense: 		req.body.expense
		}

		// TODO: validate all inputs, return BadRequest if inputs no good

		db.stocks.createStock(stock, (stockErr, stockResult) => {
			if (stockErr) {
				log.info('create_stock error createStock: ', stockErr)
				return error.InternalServerError(res)
			}

			if (stockResult === 'WD') {
				return fail(res, 'Date taken, try another one')
			}

			return success(res, stockResult)
		})
	})

	app.get('/api/all_stock', (req, res) => {
		db.stocks.getAllStocks({}, (stockErr, stockResult) => {
			if (stockErr) {
				return error.InternalServerError(res)
			} else {
				return success(res, stockResult)
			}
		})
	})

	app.get('/api/stock_by_date', (req, res) => {
		var date = req.query.date
		db.stocks.getStocks({date: date}, (stockErr, stockResult) => {
			if (stockErr) {
				return error.InternalServerError(res)
			} else {
				return success(res, stockResult)
			}
		})
	})

	app.get('/api/stock_by_year', (req, res) => {
		var year = req.query.year
		db.stocks.getStocks({year: year}, (stockErr, stockResult) => {
			if (stockErr) {
				return error.InternalServerError(res)
			} else {
				return success(res, stockResult)
			}
		})
	})

	app.post('/api/edit_stock', (req, res) => {
		let stockId = req.body.stockId,
			stock 	= req.body.stock

		if (!stockId) {
			return error.BadRequest(res, 'stockId required')
		}

		if (typeof stock !== 'object') {
			return error.BadRequest(res, 'stock should be an obejct')
		}

		db.stocks.editStockById(stockId, stock, (stockErr, stockResult) => {
			if (stockErr) {
				return error.InternalServerError(res)
			}

			if (!stockResult.success) {
				return fail(res, stockResult.reason)
			}

			return success(res, stockResult.newStock)
		})
	})

	app.post('/api/delete_stock', (req, res) => {
		var date = req.body.date

		db.stocks.deleteStock(date, (stockErr, stockResult) => {
			if (stockErr) {
				return error.InternalServerError(res)
			}

			log.debug('delete_stock successful: ', date)
			return success(res)
		})
	})
}