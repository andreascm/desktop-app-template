let Database = require('./Database')

// DATA MODEL
// stockJSON = {
// 	monthYear: '062017',
// 	initialStock: [
// 		{
// 			name: 'item name',
// 			quantity: '3'
// 		},
// 		{
// 			name: 'item name 2',
// 			quantity: '5'
// 		},
// 		...
// 	],
// 	endStock: [
// 		{
// 			name: 'item name',
// 			quantity: '8'
// 		},
// 		{
// 			name: 'item name 2',
// 			quantity: '4'
// 		},
// 		...
// 	],
// 	income: 300000,
// 	expense: 28000
// }

module.exports = class Stock extends Database {
	constructor(env) {
		super('stock', env)
	}

	//
	// Loads a single stock from database by ID and pass it to the callback function
	//
	findById(id, cb) {
		this.db.get(id, { revs_info: false}, (err, stockBody) => {
			if (err) {
				return cb('Stock findById: Error loading stock with ID: ' + id + "\n" + err, null)
			}

			return cb(null, stockBody)
		})
	}

	//
	// Loads a single stock from the database by name and pass it to the callback function
	// WARNING: if multiple stocks are found with the same name, only the first will be selected
	//
	findByDate(date, cb) {
		this.db.view('stock', 'by_date', {key: date}, (err, stockByDate) => {
			if (err) {
				console.error(err)
				return cb(err, null)
			}

			if (stockByDate.rows.length > 0) {
				return this.foundStock(stockByDate, date, cb)
			} else {
				return cb(null, null) // No stock found
			}
		})
	}

	foundStock(body, date, cb) {
		var stockList = []
		
		body.rows.forEach((stock_doc) => {
			stockList.push(stock_doc.value)
		})

		if (stockList.length === 0) {
			return cb (null, null) // No stock found
		} 

		// Found multiple stocks with same date
		if (stockList.length > 1) {
			return cb('Found multiple stocks with date: ' + date, null)
		}

		return cb(null, stockList[0])
	}

	createStock(stock, cb) {
		this.db.view('stock', 'by_date', {key: stock.monthYear}, (err, body) => {
			if (err) {
				console.error("createStock: Error loading stock with name: ", stock.name, err)
				return cb(err, null)
			}

			if (body.rows.length !== 0) {
				console.error("createStock: Cannot create stock since the name already exist: ", stock.name)
				return cb(null, "WD") // Wrong Date --> WD
			}

			var stockJSON = {
				monthYear: stock.monthYear,
				initialStock: stock.initialStock,
				endStock: stock.endStock,
				income: stock.income,
				expense: stock.expense
			}

			this.db.insert(stockJSON, (err2, body) => {
				if (err) {
					console.error("createStock: Failed to insert into stock DB", err2)
					return cb(err, null)
				}
				console.log("createStock: Stock created successfully: ", body)
				return cb(null, stockJSON)
			})
		})
	}

	deleteStock(date, cb) {
		this.db.view('stock', 'by_date', {key: date}, (err, body) => {
			if (err) {
				console.log("deleteStock: Error loading stock with date: ", date, err)
				return cb(err, null)
			}

			if (body.rows.length === 0) {
				console.log("deleteStock: No stocks found with the date: ", date)
				return cb('Stock not found', null)
			}

			if (body.rows.length > 1) {
				console.log("deleteStock: Found multiple stocks with the date: ", date)
				return cb('Multiple stocks found', null)
			}

			// TODO: delete stock
		})
	}

	editStockById(id, stock, cb) {
		this.db.get(id, (err, oldStock) => {
			if (!oldStock) {
				return cb(null, { success: false, reason: 'Cannot found stock', oldStock: null })
			}

			var newStock = {
				_id: 			oldStock._id,
				_rev: 			oldStock._rev,
				monthYear: 		stock.monthYear,
				initialStock: 	stock.initialStock,
				endStock: 		stock.endStock,
				income: 		stock.income,
				expense: 		stock.expense
			}

			this.db.insert(newStock, (err, body) => {
				if (err) {
					console.error("editStockById insert stockId: ", id, err)
					return cb(err, null)
				}
				return cb(null, { success: true, oldStock: oldStock, newStock: newStock })
			})
		})
	}

	getStocks(options, cb) {
		var opts = {
				date: 		options.date,
				year: 		options.year
			},
			result = []

		// Start from the narrowest query (smallest result) to the broadest view (largest result) before filtering by ther options
		if (opts.date) {
			this.db.view('stock', 'by_date', {key: opts.date}, (err, body) => {
				if (err) {
					console.error('getStocks: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let stock = body.rows[i].value
					result.push(stock)
				}
				cb(null, result)
			})
		} else if (opts.year) {
			this.db.view('stock', 'by_date', (err, body) => {
				if (err) {
					console.error('getStocks: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let stock = body.rows[i].value

					if (stock.monthYear.substring(2) === opts.year.toString()) {
						result.push(stock)
					}
				}

				cb(null, result)
			})
		} else {
			this.db.view('stock', 'by_id', (err, body) => {
				if (err) {
					console.error('getStocks: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let stock = body.rows[i].value
					result.push(stock)
				}
				cb(null, result)
			})
		}
	}

	getAllStocks(options, cb) {
		var opts = {
				date: 		options.date
			},
			result = []

		// Start from the narrowest query (smallest result) to the broadest view (largest result) before filtering by ther options
		if (opts.date) {
			this.db.view('stock', 'by_date', (err, body) => {
				if (err) {
					console.error('getAllStocks: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let stock = body.rows[i].value
					result.push(stock)
				}
				cb(null, result)
			})
		} else {
			this.db.view('stock', 'by_id', (err, body) => {
				if (err) {
					console.error('getAllStocks: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let stock = body.rows[i].value
					result.push(stock)
				}
				cb(null, result)
			})
		}
	}
}