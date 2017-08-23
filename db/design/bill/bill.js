module.exports = {
	"_id": "_design/user",
	"views": {
		"by_id": {
			"map": "function (doc) {\n\t\t  emit(doc._id, doc);\n\t\t}"
		},
		"by_date": {
			"map": "function (doc) {\n\t\t  emit(doc.date, doc);\n\t\t}"
		},
		"by_store_id": {
			"map": "function (doc) {\n\t\t  emit(doc.storeId, doc);\n\t\t}"
		},
		"by_type": {
			"map": "function (doc) {\n\t\t emit(doc.buy, doc);\n\t\t}" 
		}
	}
};
