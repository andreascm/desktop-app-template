let Database = require('./Database')

// DATA MODEL
// itemJSON = {
// 	name: 'admin name',
// 	password: '123456'
// }

module.exports = class Admin extends Database {
	constructor(env) {
		super('admin', env)
	}

	//
	// Loads a single admin from database by ID and pass it to the callback function
	//
	findById(id, cb) {
		this.db.get(id, { revs_info: false}, (err, adminBody) => {
			if (err) {
				return cb('Admin findById: Error loading admin with ID: ' + id + "\n" + err, null)
			}

			return cb(null, adminBody)
		})
	}

	//
	// Loads a single admin from the database by name and pass it to the callback function
	// WARNING: if multiple admins are found with the same name, only the first will be selected
	//
	findByName(name, cb) {
		this.db.view('admin', 'by_name', {key: name}, (err, adminByName) => {
			if (err) {
				console.error(err)
				return cb(err, null)
			}

			if (adminByName.rows.length > 0) {
				return this.foundAdmin(adminByName, name, cb)
			} else {
				return cb(null, null) // No admin found
			}
		})
	}

	foundAdmin(body, name, cb) {
		var adminList = []
		
		body.rows.forEach((admin_doc) => {
			adminList.push(admin_doc.value)
		})

		if (adminList.length === 0) {
			return cb (null, null) // No admin found
		} 

		// Found multiple admins with same name
		if (adminList.length > 1) {
			return cb('Found multiple admins with name: ' + name, null)
		}

		return cb(null, adminList[0])
	}

	createAdmin(admin, cb) {
		this.db.view('admin', 'by_name', {key: admin.name}, (err, body) => {
			if (err) {
				console.error("createAdmin: Error loading admin with name: ", admin.name, err)
				return cb(err, null)
			}

			if (body.rows.length !== 0) {
				console.error("createAdmin: Cannot create admin since the name already exist: ", admin.name)
				return cb(null, "WN") // Wrong Name --> WN
			}

			var adminJSON = {
				name: admin.name,
				password: admin.password
			}

			this.db.insert(adminJSON, (err2, body) => {
				if (err) {
					console.error("createAdmin: Failed to insert into admin DB", err2)
					return cb(err, null)
				}
				console.log("createAdmin: Admin created successfully: ", body)
				return cb(null, adminJSON)
			})
		})
	}

	deleteAdmin(name, cb) {
		this.db.view('admin', 'by_name', {key: name}, (err, body) => {
			if (err) {
				console.log("deleteAdmin: Error loading admin with name: ", username, err)
				return cb(err, null)
			}

			if (body.rows.length === 0) {
				console.log("deleteAdmin: No admins found with the name: ", name)
				return cb('Admin not found', null)
			}

			if (body.rows.length > 1) {
				console.log("deleteAdmin: Found multiple admins with the username: ", username)
				return cb('Multiple admins found', null)
			}

			// TODO: delete admin
		})
	}

	editAdminById(id, admin, cb) {
		this.db.get(id, (err, oldAdmin) => {
			if (!oldAdmin) {
				return cb(null, { success: false, reason: 'Cannot found admin', oldAdmin: null })
			}

			var newAdmin = {
				_id: 		oldAdmin._id,
				_rev: 		oldAdmin._rev,
				name: 		admin.name,
				password: 	admin.password
			}

			this.db.insert(newAdmin, (err, body) => {
				if (err) {
					console.error("editAdminById insert adminId: ", id, err)
					return cb(err, null)
				}
				return cb(null, { success: true, oldAdmin: oldAdmin, newAdmin: newAdmin })
			})
		})
	}

	getAdmins(options, cb) {
		var opts = {
				name: 		options.name
			},
			result = []

		// Start from the narrowest query (smallest result) to the broadest view (largest result) before filtering by ther options
		if (opts.name) {
			this.db.view('admin', 'by_name', {key: opts.username}, (err, body) => {
				if (err) {
					console.error('getAdmins: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let admin = body.rows[i].value
					result.push(admin)
				}
				cb(null, result)
			})
		} else {
			this.db.view('admin', 'by_id', (err, body) => {
				if (err) {
					console.error('getAdmins: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let admin = body.rows[i].value
					result.push(admin)
				}
				cb(null, result)
			})
		}
	}

	getAllAdmins(options, cb) {
		var opts = {
				name: 		options.name
			},
			result = []

		// Start from the narrowest query (smallest result) to the broadest view (largest result) before filtering by ther options
		if (opts.name) {
			this.db.view('admin', 'by_name', (err, body) => {
				if (err) {
					console.error('getAllAdmins: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let admin = body.rows[i].value
					result.push(admin)
				}
				cb(null, result)
			})
		} else {
			this.db.view('admin', 'by_id', (err, body) => {
				if (err) {
					console.error('getAllAdmins: ', err)
					return cb(err, null)
				}

				for (var i=0; i<body.rows.length; i++) {
					let admin = body.rows[i].value
					result.push(admin)
				}
				cb(null, result)
			})
		}
	}
}