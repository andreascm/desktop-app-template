var gulpNotify = require('gulp-notify')

module.exports = function() {
    var args = Array.prototype.slice.call(arguments)

    // Send error to notification center with gulp-notify
    gulpNotify.onError({
        title: 'Compile Error',
        message: '<%= error.message %>'
    }).apply(this, args)

    this.emit('end')
}