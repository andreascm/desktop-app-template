module.exports = {
	"_id": "_design/item",
	"views": {
		"by_id": {
			"map": "function (doc) {\n\t\t  emit(doc._id, doc);\n\t\t}"
		},
		"by_name": {
			"map": "function (doc) {\n\t\t  emit(doc.name, doc);\n\t\t}"
		}
	}
}
