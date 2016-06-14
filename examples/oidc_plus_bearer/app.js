var express = require('express');
var passport = require('passport');
var OIDCStrategy = require('../../lib/index').OIDCStrategy;
var BearerStrategy = require('../../lib/index').BearerStrategy;