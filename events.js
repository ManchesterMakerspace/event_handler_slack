// events.js ~ Copyright 2019 Manchester Makerspace ~ License MIT
var MongoClient = require('mongodb').MongoClient;
var ObjectID = require('mongodb').ObjectID;
var querystring = require('querystring');  // Parse urlencoded body
var crypto = require('crypto');            // verify request from slack is from slack with hmac-256
var https = require('https');
var request = require('request');

var mongo = {
    updateUser: function(client, memberDoc, email, event, issue){
        client.db(process.env.DB_NAME).collection('slack_users').updateOne({member_id: memberDoc._id}, {
            $set: {
                _id: new ObjectID(),
                member_id: memberDoc ? memberDoc._id : 'need member_id',
                slack_email: email ? email : 'need email',
                slack_id: event.user.id,
                name: event.user.profile.display_name,
                real_name: event.user.real_name
            }
        }, {upsert: true}, function onUpdate(error, result){
            if(updateError){issue(event, error);}
            client.close();
        });
    },
    addUser: function(event, email, issue){
        MongoClient.connect(process.env.MONGODB_URI, {useNewUrlParser: true}, function onConnect(connectError, client){
            if(client){
                if(email){
                    client.db(process.env.DB_NAME).collection('members').findOne({email: email}, function onFind(findError, memberDoc){
                        if(memberDoc){ // given we find a member with this email
                            mongo.updateUser(client, memberDoc, email, event, issue);
                        } else {client.close(); issue(event, findError);}
                    });
                } else {mongo.updateUser(client, null, null, event, issue);} // guest user case
            } else {issue(even, connectError);}
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
            if(event.body.event.type === "team_join"){
                callback(null, response);
                slack.onTeamJoin(event.body.event, slack.send);
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
    onAddIssue: function(event, error){
        slack.send('If ' + event.user.real_name +
         ' is a member they will need to be manually updated in database. Entry in collection slack_users, search {"slack_id": "' +
          event.user.id + '"} error message was:'  + error);
    },
    onTeamJoin: function(event, log){ // pass fuction on where to log (slack, cloudwatch, console, ect)
        slack.send('Welcome to the makerspace '+event.user.real_name+'! (<@'+ event.user.id +
            '>) \nThis is a good channel to introduce yourself and ask questions.', process.env.NEW_MEMBERS_WH);
        if(event.user.is_resticted){log(event.user.real_name + ' is restricted (attempting to figure if this attribute indicates guest)');}
        if(event.user.is_ultra_resticted){log(event.user.real_name + ' is ultra restricted (attempting to figure if this attribute indicates guest)');}
        slack.getEmail(event.user.id, function onEmailFind(error, email){ // this assumes the email that we intivited them to slack with is the one that gets signed in with intially, pretty sure bet
            if(!email){slack.onAddIssue(event, error);}
            mongo.addUser(event, email, slack.onAddIssue); // add user to our db regardless of finding a match
        });
    }
};

exports.incoming = slack.handler;
