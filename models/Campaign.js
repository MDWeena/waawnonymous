const mongoose = require('mongoose');
const {Schema} = mongoose;

const campaignSchema = new Schema({
    user:{
        type: mongoose.Types.ObjectId,
        ref: 'user'
    },

    messages: [{
        type: mongoose.Types.ObjectId,
        ref: 'message'
    }]
}, {timestamps: true});

const Campaign = mongoose.model('campaign', campaignSchema);

module.exports = Campaign;