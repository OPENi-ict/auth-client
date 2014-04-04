// config/auth.js

// expose our config directly to our application using module.exports
module.exports = {

	'facebookAuth' : {
		'clientID' 		: 'your-app-id', // your App ID
		'clientSecret' 	: 'your-app-secret', // your App Secret
		'callbackURL' 	: 'http://localhost:8080/auth/facebook/callback'
	},

	'twitterAuth' : {
		'consumerKey' 		: 'your-app-id',
		'consumerSecret' 	: 'your-app-secret',
		'callbackURL' 		: 'http://localhost:8080/auth/twitter/callback'
	},

	'googleAuth' : {
		'clientID' 		: 'your-app-id',
		'clientSecret' 	: 'your-app-secret',
		'callbackURL' 	: 'http://localhost:8080/auth/google/callback'
	},

	'openidgoogleAuth' : {
		'clientID' 		: 'your-app-id',
		'clientSecret' 	: 'your-app-secret',
		'callbackURL' 	: 'http://localhost:8080/auth/openidgoogle/callback'
	},

	'openidherokuAuth' : {
		'clientID' 		: 'your-app-id',
		'clientSecret' 	: 'your-app-secret',
		'callbackURL' 	: 'http://localhost:8080/auth/openidheroku/callback'
	},

	'openidOPENiAuth' : {
		'clientID' 		: 'your-app-id',
		'clientSecret' 	: 'your-app-secret',
		'callbackURL' 	: 'http://localhost:8080/auth/openidheroku/callback'
	},

	'openidLocalOPENiAuth' : {
		'clientID' 		: 'your-app-id',
		'clientSecret' 	: 'your-app-secret',
		'callbackURL' 	: 'http://localhost:8080/auth/openidlocalopeni/callback'
	}

};
