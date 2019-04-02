// events.js ~ Copyright 2019 Manchester Makerspace ~ License MIT
var MongoClient = require('mongodb').MongoClient;
var ObjectID = require('mongodb').ObjectID;
var querystring = require('querystring');  // Parse urlencoded body
var crypto = require('crypto');            // verify request from slack is from slack with hmac-256
var https = require('https');
var request = require('request');

var mongo = {
    addUser: function(event, email, log){
        MongoClient.connect(process.env.MONGODB_URI, {useNewUrlParser: true}, function onConnect(connectError, client){
            if(client){
                client.db(process.env.DB_NAME).collection('members').findOne({email: email}, function onFind(findError, memberDoc){
                    if(memberDoc){ // given we find a member with this email
                        client.db(process.env.DB_NAME).collection('slack_users').updateOne({member_id: memberDoc._id}, {
                            $set: {
                                _id: new ObjectID(),
                                member_id: memberDoc._id,
                                slack_email: email,
                                slack_id: event.user.id,
                                name: event.user.profile.display_name,
                                real_name: event.user.real_name
                            }
                        }, {upsert: true}, function onUpdate(updateError, result){
                            if(updateError){log('update error: ' + updateError);}
                            client.close();
                        });
                    } else {log('error finding member ' + findError);}
                });
            } else {log('error connectining to database to update new member: ' + connectError);}
        });
    }
};

var slack = {
    verify: function(event){
        var timestamp = event.headers['X-Slack-Request-Timestamp'];        // nonce from slack to have an idea
        var secondsFromEpoch = Math.round(new Date().getTime() / 1000);    // get current seconds from epoch because thats what we are comparing with
        if(Math.abs(secondsFromEpoch - timestamp > 60 * 5)){return false;} // make sure request isn't a duplicate
        var computedSig = 'v0=' + crypto.createHmac('sha256', process.env.SLACK_SIGNING_SECRET).update('v0:' + timestamp + ':' + event.body).digest('hex');
        return crypto.timingSafeEqual(Buffer.from(event.headers['X-Slack-Signature'], 'utf8'), Buffer.from(computedSig ,'utf8'));
    },
    send: function(msg, webhook){
        var postData = JSON.stringify({'text': msg});
        var options = {
            hostname: 'hooks.slack.com', port: 443, method: 'POST',
            path: webhook ? webhook : process.env.LOG_WH,
            headers: {'Content-Type': 'application/json','Content-Length': postData.length}
        };
        var req = https.request(options, function(res){}); // just do it, no need for response
        req.on('error', function(error){console.log(error);});
        req.write(postData); req.end();
    },
    handler: function(event, context, callback){
        var response = {statusCode:403, headers: {'Content-type': 'application/json'}};
        if(slack.verify(event)){
            response.statusCode = 200;
            try{event.body = JSON.parse(event.body);}catch(error){console.log(error); callback(null, response);}
            if(event.body.type === "team_join"){
                callback(null, response);
                slack.onTeamJoin(event.body, slack.send);
            } else if (event.body.type === "url_verification"){
                response.body = JSON.stringify({challenge: event.body.challenge});
                callback(null, response);
            } else {console.log('unhandled event type: ' + JSON.stringify(event.body)); callback(null, response);}
        } else {console.log('not slack?'); callback(null, response);}
    },
    getEmail: function(user_id, onFind){
        request({
            url: 'https://slack.com/api/users.info', method: 'GET',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            qs: {'token': process.env.BOT_TOKEN, 'user': user_id}
        }, function onResponse(error, res, body){
            if(res.statusCode === 200){
                body = JSON.parse(body);
                if(body.ok){
                    onFind(null, body.user.profile.email);
                    return;
                } else {error += JSON.stringify(body);}
            }
            onFind("lookup issue: " + res.statusCode + error, null);
        });
    },
    onTeamJoin: function(event, log){ // pass fuction on where to log (slack, cloudwatch, console, ect)
        slack.send('Welcome to the makerspace '+event.user.real_name+'! @'+ event.user.profile.display_name +
            '\nThis is a good channel to introduce yourself and ask questions.', process.env.NEW_MEMBERS_WH);
        slack.getEmail(event.user.id, function onEmailFind(error, email){ // this assumes the email that we intivited them to slack with is the one that gets signed in with intially, pretty sure bet
            if(email){mongo.addUser(event, email, log);}
            else     {log('no email: ' + error);}
        });
    }
};

exports.incoming = slack.handler;
