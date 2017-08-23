var gulpUtil        = require('gulp-util'),
    prettyHrtime    = require('pretty-hrtime')

module.exports = {
    start: function(filePath) {
        startTime = process.hrtime()
        gulpUtil.log('Bundling', gulpUtil.colors.green(filePath) + '...')
    },

    end: function(filePath) {
        var taskTime = process.hrtime(startTime),
            prettyTime = prettyHrtime(taskTime)

        gulpUtil.log('Bundled', gulpUtil.colors.green(filePath), 'in', gulpUtil.colors.magenta(prettyTime))
    }
}