var gulp        	= require('gulp'),
	uglify      	= require('gulp-uglify'),
	nodemon     	= require('gulp-nodemon'),
	watch       	= require('gulp-watch'),
	vsource     	= require('vinyl-source-stream'),
	vbuffer     	= require('vinyl-buffer'),
	browserify		= require('browserify'),
	del				= require('del'),
	watchify		= require('watchify'),
	path			= require('path'),
	glob			= require('glob'),
	bundleLogger	= require('./gulp/util/bundleLogger'),
	handleErrors	= require('./gulp/util/handleErrors'),
	babelify 		= require('babelify')

var destination = './build',
	source      = './src',
	mui 		= './node_modules/material-ui/src'
	
var	watchList   = ['app.js', 'routes.js', 'objects.js', 'db/', 'build/', 'lib/'],
	uglifyOptions = {
						output: {
							// beautify: true,
							max_line_len: 3200
						}
						// 	mangle: false,
						// 	compress: true,
						// 	preserveComments: false
					}

var	config = {
	browserify: {
		bundleConfigs: function() {
			var jsxDirs = [''],
				jsxFiles = jsxDirs.map( function(dir) {
					return glob.sync(source + '/app' + dir + '/*.jsx')
				}),
				entries = []

			for (var i=0; i<jsxFiles.length; i++) {
				entries[i] = jsxFiles[i].map( function(file) {
					return {
						entries: file,
						baseDir: jsxDirs[i],
						dest: destination + jsxDirs[i],
						outName: path.basename(file, '.jsx') + '.js'
					}
				})
			}

			// TODO: This still generates a bundle for _every_ jsx file. Ideally we want the following bundles:
			//       - all shared components (navbar etc.) --> components.js
			//       - all libraries (nano, react etc.) --> modules.js and material.js
			//       - live, map, projects, library, analytics, admin, ops gets individual file
			//       - all other front end gets individual file

			return [].concat.apply([], entries);
		}(),

		materialUI: [
			'material-ui/AppBar',
			'material-ui/AutoComplete',
			'material-ui/Avatar',
			'material-ui/Card',
			'material-ui/Checkbox',
			'material-ui/DatePicker',
			'material-ui/Dialog',
			'material-ui/Divider',
			'material-ui/DropDownMenu',
			'material-ui/FlatButton',
			'material-ui/FloatingActionButton',
			'material-ui/List',
			'material-ui/Drawer',
			'material-ui/List',
			'material-ui/Menu',
			'material-ui/MenuItem',
			'material-ui/Paper',
			'material-ui/RadioButton',
			'material-ui/RaisedButton',
			'material-ui/SelectField',
			'material-ui/Slider',
			'material-ui/Snackbar',
			'material-ui/styles',
			'material-ui/styles/baseThemes/lightBaseTheme',
			'material-ui/styles/colors',
			'material-ui/styles/getMuiTheme',
			'material-ui/styles/spacing',
			'material-ui/styles/transitions',
			'material-ui/styles/typography',
			'material-ui/Table',
			'material-ui/Tabs',
			'material-ui/TextField',
			'material-ui/TimePicker',
			'material-ui/Toolbar',
			'material-ui/utils/colorManipulator',
			'material-ui/utils/deprecatedPropType',
			'material-ui/utils/propTypes',
		],

		modules: [
			// downloaded components
			'async',
			'bowser',
			'chart.js',
			'nano',
			// Todo: need to make jquery a module with no additional html file reference.
			'react',
			'react-dom',
			'react-slick',
			'react-tap-event-plugin',
			'react-addons-pure-render-mixin',
			'request'
		],

		components: [
			'NavigationBar.jsx',
			'CloseButton.jsx',
			'AreYouSureDialog.jsx'
		],

		debug: false
	}
}

// Todo: split browserify to bundle 3 separate modules for more managable file size.
//       and no uglify for components.
config.browserify.dependencies =
	config.browserify.components.concat(
		config.browserify.materialUI,
		config.browserify.modules)

//====================================================================
// USAGE:
// gulp (or npm start)
// gulp use-staging-db
// gulp staging
// gulp production
//====================================================================

// Task: default - for local development
//      1. Nukes build directory and recompile from scratch
//      2. Watches for changes in src / dest and restart server
//      3. Automatically refresh web page based on changes (cancelled)
gulp.task('default', ['setup-for-dev'], function() {
	console.log('---> Development (using local DB)')
})

//====================================================================
// DEVELOPMENT CONVENIENCE TASKS
//====================================================================
gulp.task('setup-for-dev', ['browser-sync', 'watch-static-files'])

gulp.task('watch-static-files', function() {
	// First time, copies all static files to be in sync
	// Subsequently, only changed files are copied - incremental build
	gulp.src(source + '/www/**')
		.pipe(watch(source + '/www/**'))
		.pipe(gulp.dest(destination))
})

gulp.task('browser-sync', ['nodemon'], function() {
	// browserSync.init(config.browserSync)
})

gulp.task('nodemon', ['build'], function(cb) {
	var started = false
	return nodemon({
		script: 'app.js',
		watch: watchList,
		env: {
			'NODE_ENV': 'development'
		}
	}).on('start', function() {
		// To avoid nodemon being started multiple times
		if (!started) {
			started = true
			cb()
		}
	}).on('restart', function() {
		// browserSync.reload()
	})
})

//Task: production - for production
//      1. Like staging, plus additional alerts when server crashes (file ticket etc.)
gulp.task('production', function () {
	// TODO: Add alerts to nodemon
	nodemon({
		script: 'app.js',
		watch: [], // can I watch nothing?
		env: { 'NODE_ENV': 'production' }
	})
	console.log("---> Production")
})


//====================================================================
// BUIDLING TASKS
//====================================================================

// Task: build
gulp.task('build', ['jsdeps'], function() {
	gulp.src('./build/deps/dependencies.js')
		.pipe(uglify())
		// .pipe(uglify({
		//	mangle: false,
		//	output: {
		//		beautify: true
		//	},
		//	compress: true,
		//	preserveComments: false
		// }))
		.pipe(gulp.dest('./build/deps'))
	
	return gulp.src(source + '/www/**').pipe(gulp.dest(destination))
})

gulp.task('jsdeps', ['browserify'], function() {
	var bundler = browserify({
		// Require watchify arguments
		cache: {},
		packageCache: {},
		fullPaths: false,

		plugin: [watchify],
		paths: ['./node_modules', source + '/app/components/']
	})
	.transform("babelify", {
		presets: [
			"es2015", "es2016", "es2017", "react"
		],
		plugins: ["transform-class-properties"]
	})

	config.browserify.dependencies.map(bundler.require, bundler)

	var bundle = function() {
		bundleLogger.start('dependencies.js')

		return bundler
			.bundle()
			.on('error', handleErrors)
			.pipe(vsource('dependencies.js'))
			.pipe(gulp.dest('./build/deps'))
			.on('end', reportFinished)
	}

	bundler.on('update', bundle)

	var reportFinished = function() {
		// Log when bundling completes
		bundleLogger.end('dependencies.js')
	}

	return bundle()
})

gulp.task('browserify', ['clean'], function(cb) {
	var brconfig = config.browserify,
		bundleQueue = brconfig.bundleConfigs.length

	var browserifyThis = function(bundleConfig) {
		var bundler = browserify({
			// Require watchify arguments
			cache: {},
			packageCache: {},
			fullPaths: false,

			// Specify the entry point of your app
			entries: bundleConfig.entries,
			// Add file extentions to make optional in your requires
			extensions: brconfig.extensions,

			paths: ['./node_modules', source + '/app/components/'],
			// Enable source maps,
			debug: brconfig.debug
		})
		.transform("babelify", {
			presets: [
				"es2015", "es2016", "es2017", "react"
			],
			plugins: ["transform-class-properties"]
		})

		brconfig.dependencies.map(bundler.external, bundler)
		brconfig.materialUI.map(bundler.external, bundler)

		var bundle = function() {
			// Log when bundling starts
			bundleLogger.start(bundleConfig.outName)

			return bundler
				.bundle()
				// Report compile errors
				.on('error', handleErrors)
				// Use vinyl-source-stream to make the
				// stream gulp compatible. Specifiy the
				// desired output filename here.
				.pipe(vsource(bundleConfig.outName))
				// http://stackoverflow.com/questions/24992980/how-to-uglify-output-with-browserify-in-gulp
				// comment the next two lines if you find building takes too long for development
				// .pipe(vbuffer())
				// .pipe(uglify())
				// Specify the output destination
				.pipe(gulp.dest(bundleConfig.dest))
				.on('end', reportFinished)
		}

		// Wrap with watchify and rebundle on changes
		bundler = watchify(bundler)
		// Rebundle on update
		bundler.on('update', bundle)

		var reportFinished = function() {
			// Log when bundling completes
			bundleLogger.end(bundleConfig.outName)

			if (bundleQueue) {
				bundleQueue--
				if (bundleQueue === 0) {
					// If queue is empty, tell gulp the task is complete.
					// https://github.com/gulpjs/gulp/blob/master/docs/API.md#accept-a-callback
					cb()
				}
			}
		}

		return bundle()
	}

	// Start bundling with Browserify for each bundleConfig specified
	brconfig.bundleConfigs.forEach(browserifyThis)
})

// Task: clean
gulp.task('clean', function() {
	del.sync(['./build/**'])
})