var express = require('express');
const path = require("path");
const app = require("../app");
var router = express.Router();

/* GET users listing. */
router.get('/', function(req, res, next) {
  res.sendFile(app.dir + '/shop.html')
});

module.exports = router;
