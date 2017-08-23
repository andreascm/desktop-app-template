// Nodejs
var fs = require('fs'),
	path = require('path'),
	chalk = require('chalk')

// Database
let db = require('./db')

// Expressjs
var express = require('express'),
	compression = require('compression'),
	app = express(),
	bodyParser = require('body-parser'),
// var router = express.Router(); // will bring this back into routes.js in the future
	winston = require('winston'),
	expressLogger = require('express-winston'),
	log = new (winston.Logger)({
		level: (process.env.NODE_ENV === 'production' || process.env.NODE_ENV === 'staging' ? 'info' : 'debug'),
		transports: [
			new (winston.transports.Console)({
				json: false,
				timestamp: () => {
					return (new Date()).toISOString().replace('T',' ').replace('Z','')
				},
				formatter: (opts) => {
					return opts.timestamp() + ' [' + opts.level + '] ' +
						(undefined !== opts.message ? opts.message : '')
				}
			})
		]
	})

log.setLevels(winston.config.syslog.levels); // to match syslog levels
// Avoid: { emerg: 0, alert: 1, crit: 2 } in application unless platform / hardware issue
// Use:   { error: 3, warning: 4, notice: 5, info: 6, debug: 7 }
app.use(compression())

app.use(bodyParser.json({ limit: '42mb' })); // to support JSON-encoded bodies
app.use(bodyParser.urlencoded({ extended: true })); // to support URL-encoded bodies


// Cookies and Session
app.use(require('cookie-parser')())
app.use(require('express-session')({
	secret: 'store',
	cookie: { maxAge: 12 * 60 * 60 * 1000, secure: true }, // 12 hours
	resave: false,
	saveUninitialized: false }))

let port   = process.env.PORT || 3000,
	server = app.listen(port)
log.info('Server listening on port ' + port)

// Passportjs
let passport = require('passport'),
	bcrypt = require('bcryptjs'),
	salt = bcrypt.genSaltSync(10),
	LocalStrategy = require('passport-local').Strategy

passport.use(new LocalStrategy(
	function(username, password, cb) {
		db.admins.findByName(username, function(err, admin) {
			if (err) {
				log.error('Error while authenticating Admin: ' + err)
				return cb(err)
			}

			if (!admin) {
				log.info('No admin found: Admin')
				return cb(null, false, { message: 'Incorrect admin or password' })
			}

			if (!bcrypt.compareSync(password, admin.password)) {
				log.info('Incorrect password for admin: Admin')
				return cb(null, false, { message: 'Incorrect admin or password' })
			}

			log.info('Admin logged in: Admin')
			return cb(null, admin)
		})
	}
))

passport.serializeUser(function(admin, cb) {
	cb(null, admin._id)
})

passport.deserializeUser(function(id, cb) {
	db.admins.findById(id, function(err, admin) {
		if (err) {
			log.debug('findById: ', err)
			return cb(null, null)
		}

		cb(null, admin)
	})
})

app.use(passport.initialize())
app.use(passport.session())

// Reactjs
var reactViews = require('express-react-views')
app.set('view engine', 'jsx')
app.engine('jsx', reactViews.createEngine())
app.set('views', __dirname + '/build')


// Serve Static Files 

// todo: set to syslog levels
// todo: configure 2 transports for the default logger: Console (lines) and File (json with metadata)
//       https://github.com/winstonjs/winston
app.enable('trust proxy') // staging we are behind virtualbox, producton we are behind nginx
app.use(expressLogger.logger({
	winstonInstance: log,
	msg: chalk.grey("{{req.method}} {{req.url}} {{res.statusCode}} {{res.responseTime}}ms {{req.ip}}"),
	colorize: true,
	level: 'info',
	meta: false
}))
// Todo: define different caching policies for development, staging and production.

// isomorphic (used by client and server)
app.use('/lib', express.static(path.join(__dirname, '/lib'), { maxAge: '1m' })) // moving out to top directory from /build/lib
app.use('/.well-known', express.static(path.join(__dirname, '/.well-known'))) // required for SSL cert autorenew

// client side (maxAge syntax: https://www.npmjs.com/package/ms)
app.use('/bower_components', express.static(path.join(__dirname, '/build/bower_components'), { maxAge: '1h' })) // old static lib folder - to deprecate in favour of /lib
app.use('/img', express.static(path.join(__dirname, '/build/img'), { maxAge: '1m' }))
app.use('/css', express.static(path.join(__dirname, '/build/css'), { maxAge: '1m' }))
app.use('/js', express.static(path.join(__dirname, '/build/js'), { maxAge: '1m' }))
app.use('/fonts', express.static(path.join(__dirname, '/build/fonts'), { maxAge: '1h' }))
app.use('/deps', express.static(path.join(__dirname, '/build/deps'), { maxAge: '1m' }))
// temp - to reconsider how to manage PDFs
app.use('/help', express.static(path.join(__dirname, '/build/help'), { maxAge: '1m' }))


// Middleware to handle CORS 
let allowedDomains = [
	// Add domains here if you want to test new domains (the default is the first one)
	'localhost:3000'
]
let allowCrossDomain = function(req, res, next) {
	let atLeastOneHeader = false
	if (req.headers.origin) {
		let origin = allowedDomains.indexOf(req.header('host').toLowerCase()) > -1 ? req.headers.origin : allowedDomains[0]
		res.header('Access-Control-Allow-Origin', origin)
		atLeastOneHeader = true
	}
	if (req.headers['access-control-request-method']) {
		res.header('Access-Control-Allow-Methods', req.headers['access-control-request-method'])
		atLeastOneHeader = true
	}
	if (req.headers['access-control-request-headers']) {
		res.header('Access-Control-Allow-Headers', req.headers['access-control-request-headers'])
		atLeastOneHeader = true
	}
	if (atLeastOneHeader) {
		res.header('Access-Control-Max-Age', 60 * 60 * 24 * 365)
	}
	// intercept OPTIONS method
	if (atLeastOneHeader && req.method === 'OPTIONS') {
		res.send(200)
	}
	else {
		next()
	}
}
app.use(allowCrossDomain)


// Manage routes and log them

require('./routes')(app, server, log)  // Web facing, with real visible URLs
require('./objects')(app, server, log) // Ajax calls from within React

//
// Finally, if no middleware matches, send a 404 page.
//
// app.use(function(req, res, next) {
//	res.status(404).sendFile(__dirname + '/build/notfound.html')
	// no need to call next (for express to 404) because I have my own 404
// })

app.use(expressLogger.errorLogger({
	winstonInstance: log
}))