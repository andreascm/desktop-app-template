module.exports = {
	"_id": "_design/stock",
	"views": {
		"by_id": {
			"map": "function (doc) {\n\t\t  emit(doc._id, doc);\n\t\t}"
		},
		"by_date": {
			"map": "function (doc) {\n\t\t  emit(doc.monthYear, doc);\n\t\t}"
		}
	}
}
