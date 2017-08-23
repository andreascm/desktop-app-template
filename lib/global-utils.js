"use strict"

//
// Colors
//
var grey 		= '#DDDDDD'
var	red 		= '#FF4081'

//
// JSON MANIPULATION
//
var acceptedTypes = ["GET", "POST", "PUT", "DELETE"]
// @param {string, json}
// @returns the XHR result from jQuery

var postJSON = (url, data) => {
	return $.ajax({
		type: 'POST',
		url: url,
		data: data,
		contentType: 'application/json; charset=utf-8',
		dataType: 'json'
	})
}

var putJSON = (url, data) => {
	return $.ajax({
		type: 'PUT',
		url: url,
		data: data,
		contentType: 'application/json; charset=utf-8',
		dataType: 'json'
	})
}

var deleteJSON = (url, data) => {
	return $.ajax({
		type: 'DELETE',
		url: url,
		data: data,
		contentType: 'application/json; charset=utf-8',
		dataType: 'json'
	})
}

var reqJSON = (type, url, data) => {
	var upperType = type.toUpperCase()

	if (acceptedTypes.indexOf(upperType)) {
		return $.ajax({
			type: upperType,
			url: url,
			data: data,
			contentType: 'application/json; charset=utf-8',
			dataType: 'json'
		})
	} else {
		return console.error('Invalid request type')
	}
}

//
// URL MANIPULATION
//

// @param {String} param 
// @returns the value of parameter from the window's query string
var getQueryVariable = (param) => {
	var query = window.location.search.substring(1) // eliminate '?'
	var vars = query.split("&")
	for (var i=0; i<vars.length; i++) {
		var pair = vars[i].split("=")
		if (pair[0] == param) {
			return pair[1]
		}
	}
}

//
// DATE MANIPULATION
//
var dayddmmyyyy = (date) => {
	var day = date.getDay(),
		dd = date.getDate(),
		mm = date.getMonth(),
		yyyy = date.getFullYear(),
		days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'],
		months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

	return days[day] + ', ' + dd + ' ' + months[mm] + ' ' + yyyy
}

//
// NUMBER MANIPULATION
//
var priceDotSeparator = (num) => {
	var numString = '',
		number = num
	while (number/1000 >= 1) {
		var numToAdd = number%1000
		if (numToAdd === 0) {
			numString = '.000' + numString
		} else {
			numString = '.' + numToAdd.toString() + numString
		}
		number = parseInt(number/1000)
	}
	numString = number.toString() + numString
	return numString
}

var priceCommaSeparator = (num) => {
	var numString = '',
		number = num
	while (number/1000 >= 1) {
		var numToAdd = number%1000
		if (numToAdd === 0) {
			numString = ',000' + numString
		} else {
			numString = ',' + numToAdd.toString() + numString
		}
		number = parseInt(number/1000)
	}
	numString = number.toString() + numString
	return numString
}