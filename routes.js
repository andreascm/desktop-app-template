let path     = require('path'),
	url      = require('url'),
	passport = require('passport'),
	bcrypt 	 = require('bcryptjs'),
	salt 	 = bcrypt.genSaltSync(10),
	db 		 = require('./db')

// Send the file (regardless whether logged in or out)
function sendFile(file) {
	return function(req, res) {
		res.sendFile(__dirname + file)
	}
}

// Send the file if user is logged in
function sendFileIfLoggedIn(file, returnTo) {
	return function(req, res) {
		if (!req.user) {
			if (path.extname(file) === '.js') {
				res.sendStatus(401)
			} else {
				var querystring = url.parse(req.url, false).query
				// current catch all, including .html (revisit if there're additional extensions)
				req.session.returnTo = returnTo + (querystring ? ('?' + querystring) : '')
			}
		} else {
			res.sendFile(__dirname + file)
		}
	}
}

// Execute the callback if the user is logged in
function callbackIfLoggedIn(cb, returnTo) {
	return function(req, res) {
		if (!req.user) {
			var querystring = url.parse(req.url, false).query
			// to revisit: js also redirects
			req.session.returnTo = returnTo + (querystring ? ('?' + querystring) : '')
		} else {
			cb(req, res)
		}
	}
}

//
// Routes
//
module.exports = function(app, server, log) {

	// Neat wrappers for the above
	function access(url, file) {
		app.get(url, sendFileIfLoggedIn(file, url))
	}
	function send(url, file) {
		app.get(url, sendFile(file))
	}
	function redirect(url, newUrl) {
		app.get(url, function(req, res) { res.redirect(newUrl) })
	}
	
	// potentially dynamic homepage
	app.get('/', function(req, res) {
		res.sendFile(__dirname + '/build/index.html')
	})

	app.post('/passwordCheck', function(req, res) {
		passport.authenticate('local', function(err, admin, info) {
			if (err) {
				log.error('passport.authenticate error: ', err)
				return res.sendStatus(500)
			}

			if (!admin) {
				log.info('passport.authenticate: login failed')
				return res.redirect('/?login=failed')
			}

			req.login(admin, function(err) {
				if (err) {
					log.error('passport.authenticate: req.login: ', err, admin)
					return res.redirect('/?login=failed')
				}

				var successRedirectURL = req.session.returnTo || req.body.returnTo || '/sell'
				delete req.session.returnTo

				return res.redirect(successRedirectURL)
			})
		})(req, res)
	})

	app.post('/changeUsername', function(req, res) {
		passport.authenticate('local', function(err, admin, info) {
			if (err) {
				log.error('passport.authenticate error: ', err)
				return res.sendStatus(500)
			}

			if (!admin) {
				log.info('passport.authenticate: login failed')
				return res.redirect('/?login=failed')
			}

			var newAdmin = admin

			req.login(admin, (err) => {
				if (err) {
					log.error('passport.authenticate: req.login: ', err, admin)
					return res.redirect('/?login=failed')
				}

				
				newAdmin.name = req.body.newUsername

				db.admins.editAdminById(newAdmin._id, newAdmin, (adminErr, adminResult) => {
					if (adminErr) {
						return res.redirect('/?error=Failed to change username')
					}

					if (!adminResult.success) {
						return res.redirect('/?error=Failed to change username')
					}

					var successRedirectURL = req.session.returnTo || req.body.returnTo || '/?success=Username changed successfully'
					delete req.session.returnTo

					return res.redirect(successRedirectURL)
				})
			})
		})(req, res)
	})

	app.post('/changePassword', function(req, res) {
		passport.authenticate('local', function(err, admin, info) {
			if (err) {
				log.error('passport.authenticate error: ', err)
				return res.sendStatus(500)
			}

			if (!admin) {
				log.info('passport.authenticate: login failed')
				return res.redirect('/?login=failed')
			}

			var newAdmin = admin

			req.login(admin, (err) => {
				if (err) {
					log.error('passport.authenticate: req.login: ', err, admin)
					return res.redirect('/?login=failed')
				}

				
				newAdmin.password = bcrypt.hashSync(req.body.newPassword, salt)

				db.admins.editAdminById(newAdmin._id, newAdmin, (adminErr, adminResult) => {
					if (adminErr) {
						return res.redirect('/?error=Failed to change password')
					}

					if (!adminResult.success) {
						return res.redirect('/?error=Failed to change password')
					}

					var successRedirectURL = req.session.returnTo || req.body.returnTo || '/?success=Password changed successfully'
					delete req.session.returnTo

					return res.redirect(successRedirectURL)
				})
			})
		})(req, res)
	})

	app.get('/logout', function(req, res) {
		req.logout()
		req.session.destroy((err) => res.redirect('/'))
	})

	//
	// Internal facing pages
	//
	send('/index', '/build/index.html')
	send('/index.js', '/build/index.js')
}

