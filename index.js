const express = require('express')
const cors = require('cors');
const dns = require('dns');
// Configure public DNS resolvers to handle MongoDB SRV queries correctly
dns.setServers(['8.8.8.8', '1.1.1.1']);
const app = express();
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const stripe = require('stripe')(process.env.STRIPE_SECRET);

const port = process.env.PORT || 5000;
const crypto = require("crypto");

const admin = require("firebase-admin");

if (process.env.FB_SERVICE_KEY) {
    try {
        const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8')
        const serviceAccount = JSON.parse(decoded);

        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount)
        });
        console.log("Firebase Admin initialized successfully.");
    } catch (err) {
        console.error("Failed to parse FB_SERVICE_KEY or initialize Firebase Admin:", err.message);
    }
} else {
    console.warn("WARNING: FB_SERVICE_KEY is not defined in the environment. Firebase authentication will fail.");
}


function generateTrackingId() {
    const prefix = "PRCL"; // your brand prefix
    const date = new Date().toISOString().slice(0, 10).replace(/-/g, ""); // YYYYMMDD
    const random = crypto.randomBytes(3).toString("hex").toUpperCase(); // 6-char random hex

    return `${prefix}-${date}-${random}`;
}

// middleware
app.use(express.json());
app.use(cors());

const verifyFBToken = async (req, res, next) => {
    const token = req.headers.authorization;

    if (!token) {
        return res.status(401).send({ message: 'unauthorized access' })
    }

    try {
        const idToken = token.split(' ')[1];
        let decoded;
        if (process.env.FB_SERVICE_KEY) {
            decoded = await admin.auth().verifyIdToken(idToken);
        } else {
            // Local development fallback: Decode JWT payload directly without verification
            const payloadBase64 = idToken.split('.')[1];
            decoded = JSON.parse(Buffer.from(payloadBase64, 'base64').toString('utf8'));
        }
        console.log('decoded in the token', decoded);
        req.decoded_email = decoded.email;
        next();
    }
    catch (err) {
        console.error("Token verification failed:", err.message);
        return res.status(401).send({ message: 'unauthorized access' })
    }
}

const uri = process.env.MONGODB_URI || `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.vyznij5.mongodb.net/?appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});


async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect();

        const db = client.db('zap_shift_db');
        const userCollection = db.collection('users');
        const parcelsCollection = db.collection('parcels');
        const paymentCollection = db.collection('payments');
        const ridersCollection = db.collection('riders');
        const trackingsCollection = db.collection('trackings');

        // middle admin before allowing admin activity
        // must be used after verifyFBToken middleware
        const verifyAdmin = async (req, res, next) => {
            const email = req.decoded_email;
            const query = { email };
            const user = await userCollection.findOne(query);

            if (!user || user.role !== 'admin') {
                return res.status(403).send({ message: 'forbidden access' });
            }

            next();
        }
        const verifyRider = async (req, res, next) => {
            const email = req.decoded_email;
            const query = { email };
            const user = await userCollection.findOne(query);

            if (!user || user.role !== 'rider') {
                return res.status(403).send({ message: 'forbidden access' });
            }

            next();
        }

        const logTracking = async (trackingId, status) => {
            const log = {
                trackingId,
                status,
                details: status.split('_').join(' '),
                createdAt: new Date()
            }
            const result = await trackingsCollection.insertOne(log);
            return result;
        }

        // users related apis
        app.get('/users', verifyFBToken, async (req, res) => {
            const searchText = req.query.searchText;
            const role = req.query.role;
            const query = {};

            if (searchText) {
                query.$or = [
                    { displayName: { $regex: searchText, $options: 'i' } },
                    { email: { $regex: searchText, $options: 'i' } },
                ]
            }

            if (role) {
                query.role = role;
            }

            const cursor = userCollection.find(query).sort({ createdAt: -1 }).limit(100);
            const result = await cursor.toArray();
            res.send(result);
        });

        app.get('/users/:id', verifyFBToken, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }
            const user = await userCollection.findOne(query);
            
            // Users can only view their own profile, or admins can view any
            if (user && user.email !== req.decoded_email) {
                const currentUser = await userCollection.findOne({ email: req.decoded_email });
                if (!currentUser || currentUser.role !== 'admin') {
                    return res.status(403).send({ message: 'forbidden access' });
                }
            }
            
            res.send(user);
        })

        app.get('/users/:email/role', verifyFBToken, async (req, res) => {
            const email = req.params.email;
            
            // Users can only check their own role, or admins can check any
            if (email !== req.decoded_email) {
                const currentUser = await userCollection.findOne({ email: req.decoded_email });
                if (!currentUser || currentUser.role !== 'admin') {
                    return res.status(403).send({ message: 'forbidden access' });
                }
            }
            
            const query = { email }
            const user = await userCollection.findOne(query);
            res.send({ role: user?.role || 'user' })
        })

        app.post('/users', async (req, res) => {
            const user = req.body;
            user.role = 'user';
            user.createdAt = new Date();
            const email = user.email;
            const userExists = await userCollection.findOne({ email })

            if (userExists) {
                return res.send({ message: 'user exists' })
            }

            const result = await userCollection.insertOne(user);
            res.send(result);
        })

        app.patch('/users/:id/role', verifyFBToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const roleInfo = req.body;
            const query = { _id: new ObjectId(id) }
            const updatedDoc = {
                $set: {
                    role: roleInfo.role
                }
            }
            const result = await userCollection.updateOne(query, updatedDoc)
            res.send(result);
        })

        // parcel api
        app.get('/parcels', verifyFBToken, async (req, res) => {
            const query = {}
            const { email, deliveryStatus } = req.query;
            const currentUser = await userCollection.findOne({ email: req.decoded_email });

            // Non-admin users can only see their own parcels
            if (!currentUser || currentUser.role !== 'admin') {
                query.senderEmail = req.decoded_email;
            } else if (email) {
                // Admins can filter by email
                query.senderEmail = email;
            }

            if (deliveryStatus) {
                query.deliveryStatus = deliveryStatus
            }

            const options = { sort: { createdAt: -1 } }

            const cursor = parcelsCollection.find(query, options);
            const result = await cursor.toArray();
            res.send(result);
        })

        app.get('/parcels/rider', verifyFBToken, verifyRider, async (req, res) => {
            const { deliveryStatus } = req.query;
            const query = {}

            // Riders can only see their own parcels
            query.riderEmail = req.decoded_email;

            if (deliveryStatus !== 'parcel_delivered') {
                // query.deliveryStatus = {$in: ['driver_assigned', 'rider_arriving']}
                query.deliveryStatus = { $nin: ['parcel_delivered'] }
            }
            else {
                query.deliveryStatus = deliveryStatus;
            }

            const cursor = parcelsCollection.find(query)
            const result = await cursor.toArray();
            res.send(result);
        })

        app.get('/parcels/:id', verifyFBToken, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }
            const parcel = await parcelsCollection.findOne(query);
            
            if (!parcel) {
                return res.status(404).send({ message: 'parcel not found' });
            }
            
            const currentUser = await userCollection.findOne({ email: req.decoded_email });
            // Users can only view their own parcels, riders can view assigned parcels, admins can view any
            const isOwner = parcel.senderEmail === req.decoded_email;
            const isAssignedRider = parcel.riderEmail === req.decoded_email;
            const isAdmin = currentUser && currentUser.role === 'admin';
            
            if (!isOwner && !isAssignedRider && !isAdmin) {
                return res.status(403).send({ message: 'forbidden access' });
            }
            
            res.send(parcel);
        })

        app.get('/parcels/delivery-status/stats', verifyFBToken, verifyAdmin, async (req, res) => {
            const pipeline = [
                {
                    $group: {
                        _id: '$deliveryStatus',
                        count: { $sum: 1 }
                    }
                },
                {
                    $project: {
                        status: '$_id',
                        count: 1,
                        // _id: 0
                    }
                }
            ]
            const result = await parcelsCollection.aggregate(pipeline).toArray();
            res.send(result);
        })

        app.post('/parcels', verifyFBToken, async (req, res) => {
            const parcel = req.body;
            const trackingId = generateTrackingId();
            // parcel created time
            parcel.createdAt = new Date();
            parcel.trackingId = trackingId;
            // Ensure senderEmail matches authenticated user
            parcel.senderEmail = req.decoded_email;

            logTracking(trackingId, 'parcel_created');

            const result = await parcelsCollection.insertOne(parcel);
            res.send({
                insertedId: result.insertedId,
                trackingId: trackingId
            })
        })

        app.patch('/parcels/:id/status', verifyFBToken, async (req, res) => {
            const { deliveryStatus, riderId, trackingId } = req.body;
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }
            
            // Check if parcel exists and user has permission
            const parcel = await parcelsCollection.findOne(query);
            if (!parcel) {
                return res.status(404).send({ message: 'parcel not found' });
            }
            
            const currentUser = await userCollection.findOne({ email: req.decoded_email });
            const isRider = currentUser && currentUser.role === 'rider';
            const isAdmin = currentUser && currentUser.role === 'admin';
            const isAssignedRider = parcel.riderEmail === req.decoded_email;
            
            // Only assigned riders or admins can update parcel status
            if (!isAdmin && !(isRider && isAssignedRider)) {
                return res.status(403).send({ message: 'forbidden access' });
            }
            
            const updatedDoc = {
                $set: {
                    deliveryStatus: deliveryStatus
                }
            }

            if (deliveryStatus === 'parcel_delivered') {
                // update rider information
                const riderQuery = { _id: new ObjectId(riderId) }
                const riderUpdatedDoc = {
                    $set: {
                        workStatus: 'available'
                    }
                }
                const riderResult = await ridersCollection.updateOne(riderQuery, riderUpdatedDoc);
            }

            const result = await parcelsCollection.updateOne(query, updatedDoc)
            // log tracking
            logTracking(trackingId, deliveryStatus);

            res.send(result);
        })

        // TODO: rename this to be specific like /parcels/:id/assign
        app.patch('/parcels/:id', verifyFBToken, verifyAdmin, async (req, res) => {
            const { riderId, riderName, riderEmail, trackingId } = req.body;
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }

            const updatedDoc = {
                $set: {
                    deliveryStatus: 'driver_assigned',
                    riderId: riderId,
                    riderName: riderName,
                    riderEmail: riderEmail
                }
            }

            const result = await parcelsCollection.updateOne(query, updatedDoc)

            // update rider information
            const riderQuery = { _id: new ObjectId(riderId) }
            const riderUpdatedDoc = {
                $set: {
                    workStatus: 'in_delivery'
                }
            }
            const riderResult = await ridersCollection.updateOne(riderQuery, riderUpdatedDoc);

            // log  tracking
            logTracking(trackingId, 'driver_assigned')

            res.send(riderResult);

        })

        app.delete('/parcels/:id', verifyFBToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }

            const result = await parcelsCollection.deleteOne(query);
            res.send(result);
        })


        // payment related apis
        app.post('/payment-checkout-session', async (req, res) => {
            const parcelInfo = req.body;
            const amount = parseInt(parcelInfo.cost) * 100;
            const session = await stripe.checkout.sessions.create({
                line_items: [
                    {
                        price_data: {
                            currency: 'usd',
                            unit_amount: amount,
                            product_data: {
                                name: `Please pay for: ${parcelInfo.parcelName}`
                            }
                        },
                        quantity: 1,
                    },
                ],
                mode: 'payment',
                metadata: {
                    parcelId: parcelInfo.parcelId,
                    trackingId: parcelInfo.trackingId
                },
                customer_email: parcelInfo.senderEmail,
                success_url: `${process.env.SITE_DOMAIN}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
                cancel_url: `${process.env.SITE_DOMAIN}/dashboard/payment-cancelled`,
            })

            res.send({ url: session.url })
        })

        app.patch('/payment-success', async (req, res) => {
            const sessionId = req.query.session_id;
            const session = await stripe.checkout.sessions.retrieve(sessionId);

            // console.log('session retrieve', session)
            const transactionId = session.payment_intent;
            const query = { transactionId: transactionId }

            const paymentExist = await paymentCollection.findOne(query);
            // console.log(paymentExist);
            if (paymentExist) {
                return res.send({
                    message: 'already exists',
                    transactionId,
                    trackingId: paymentExist.trackingId
                })
            }

            // use the previous tracking id created during the parcel create which was set to the session metadata during session creation
            const trackingId = session.metadata.trackingId;

            if (session.payment_status === 'paid') {
                const id = session.metadata.parcelId;
                const query = { _id: new ObjectId(id) }
                const update = {
                    $set: {
                        paymentStatus: 'paid',
                        deliveryStatus: 'pending-pickup'
                    }
                }

                const result = await parcelsCollection.updateOne(query, update);

                const payment = {
                    amount: session.amount_total / 100,
                    currency: session.currency,
                    customerEmail: session.customer_email,
                    parcelId: session.metadata.parcelId,
                    parcelName: session.metadata.parcelName,
                    transactionId: session.payment_intent,
                    paymentStatus: session.payment_status,
                    paidAt: new Date(),
                    trackingId: trackingId
                }


                const resultPayment = await paymentCollection.insertOne(payment);

                logTracking(trackingId, 'parcel_paid')

                return res.send({
                    success: true,
                    modifyParcel: result,
                    trackingId: trackingId,
                    transactionId: session.payment_intent,
                    paymentInfo: resultPayment
                })
            }
            return res.send({ success: false })
        })

        // payment related apis
        app.get('/payments', verifyFBToken, async (req, res) => {
            const email = req.query.email;
            const query = {}

            // console.log( 'headers', req.headers);

            if (email) {
                query.customerEmail = email;

                // check email address
                if (email !== req.decoded_email) {
                    return res.status(403).send({ message: 'forbidden access' })
                }
            }
            const cursor = paymentCollection.find(query).sort({ paidAt: -1 });
            const result = await cursor.toArray();
            res.send(result);
        })

        // riders related apis
        app.get('/riders', verifyFBToken, async (req, res) => {
            const { status, district, workStatus } = req.query;
            const query = {}

            if (status) {
                query.status = status;
            }
            if (district) {
                query.district = district
            }
            if (workStatus) {
                query.workStatus = workStatus
            }

            const cursor = ridersCollection.find(query)
            const result = await cursor.toArray();
            res.send(result);
        })

        app.get('/riders/delivery-per-day', verifyFBToken, verifyRider, async (req, res) => {
            // Riders can only see their own delivery stats
            const email = req.decoded_email;
            // aggregate on parcel
            const pipeline = [
                {
                    $match: {
                        riderEmail: email,
                        deliveryStatus: "parcel_delivered"
                    }
                },
                {
                    $lookup: {
                        from: "trackings",
                        localField: "trackingId",
                        foreignField: "trackingId",
                        as: "parcel_trackings"
                    }
                },
                {
                    $unwind: "$parcel_trackings"
                },
                {
                    $match: {
                        "parcel_trackings.status": "parcel_delivered"
                    }
                },
                {
                    // convert timestamp to YYYY-MM-DD string
                    $addFields: {
                        deliveryDay: {
                            $dateToString: {
                                format: "%Y-%m-%d",
                                date: "$parcel_trackings.createdAt"
                            }
                        }
                    }
                },
                {
                    // group by date
                    $group: {
                        _id: "$deliveryDay",
                        deliveredCount: { $sum: 1 }
                    }
                }
            ];

            const result = await parcelsCollection.aggregate(pipeline).toArray();
            res.send(result);
        })

        app.post('/riders', async (req, res) => {
            const rider = req.body;
            rider.status = 'pending';
            rider.createdAt = new Date();

            const result = await ridersCollection.insertOne(rider);
            res.send(result);
        })

        app.patch('/riders/:id', verifyFBToken, verifyAdmin, async (req, res) => {
            const status = req.body.status;
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }
            const updatedDoc = {
                $set: {
                    status: status,
                    workStatus: 'available'
                }
            }

            const result = await ridersCollection.updateOne(query, updatedDoc);

            if (status === 'approved') {
                const email = req.body.email;
                const userQuery = { email }
                const updateUser = {
                    $set: {
                        role: 'rider'
                    }
                }
                const userResult = await userCollection.updateOne(userQuery, updateUser);
            } else if (status === 'reject' || status === 'rejected') {
                const email = req.body.email;
                const userQuery = { email }
                const updateUser = {
                    $set: {
                        role: 'user'
                    }
                }
                const userResult = await userCollection.updateOne(userQuery, updateUser);
            }

            res.send(result);
        })

        // public tracking API
        app.get('/public/track/:trackingId', async (req, res) => {
            try {
                const trackingId = req.params.trackingId;
                const parcel = await parcelsCollection.findOne({ trackingId: trackingId });
                if (!parcel) {
                    return res.status(404).send({ error: 'Parcel not found' });
                }
                const logs = await trackingsCollection.find({ trackingId: trackingId }).toArray();
                res.send({ parcel, logs });
            } catch (error) {
                res.status(500).send({ error: error.message });
            }
        });

        // tracking related apis
        app.get('/trackings/:trackingId/logs', verifyFBToken, async (req, res) => {
            const trackingId = req.params.trackingId;
            
            // Check if user has access to this tracking (via parcel ownership or assignment)
            const parcel = await parcelsCollection.findOne({ trackingId });
            if (!parcel) {
                return res.status(404).send({ message: 'tracking not found' });
            }
            
            const currentUser = await userCollection.findOne({ email: req.decoded_email });
            const isOwner = parcel.senderEmail === req.decoded_email;
            const isAssignedRider = parcel.riderEmail === req.decoded_email;
            const isAdmin = currentUser && currentUser.role === 'admin';
            
            if (!isOwner && !isAssignedRider && !isAdmin) {
                return res.status(403).send({ message: 'forbidden access' });
            }
            
            const query = { trackingId };
            const result = await trackingsCollection.find(query).toArray();
            res.send(result);
        })

        // ZAPSHIFT Extended APIs

        // User stats endpoint
        app.get('/parcels/stats/user', verifyFBToken, async (req, res) => {
            const email = req.decoded_email;
            const pipeline = [
                { $match: { senderEmail: email } },
                { $group: { _id: "$deliveryStatus", count: { $sum: 1 } } }
            ];
            const result = await parcelsCollection.aggregate(pipeline).toArray();
            res.send(result);
        });

        // User tracking logs endpoint
        app.get('/trackings/user', verifyFBToken, async (req, res) => {
            const email = req.decoded_email;
            const userParcels = await parcelsCollection.find({ senderEmail: email }).toArray();
            const trackingIds = userParcels.map(p => p.trackingId).filter(Boolean);
            if (trackingIds.length === 0) {
                return res.send([]);
            }
            const logs = await trackingsCollection.find({ trackingId: { $in: trackingIds } }).sort({ createdAt: -1 }).toArray();
            res.send(logs);
        });

        // Admin stats dashboard endpoint
        app.get('/admin/stats', verifyFBToken, verifyAdmin, async (req, res) => {
            const customersCount = await userCollection.countDocuments({ role: 'user' });
            const ridersCount = await userCollection.countDocuments({ role: 'rider' });
            const parcelsDelivered = await parcelsCollection.countDocuments({ deliveryStatus: 'delivered' });
            const serviceCentersCount = 20; // Static count matching warehouses length approx
            const payments = await paymentCollection.find({}).toArray();
            const totalEarning = payments.reduce((acc, curr) => acc + (curr.amount || 0), 0);

            res.send({
                customersCount,
                ridersCount,
                parcelsDelivered,
                serviceCentersCount,
                totalEarning
            });
        });

        // Admin rechart data endpoint
        app.get('/admin/stats/rechart', verifyFBToken, verifyAdmin, async (req, res) => {
            const pipeline = [
                {
                    $group: {
                        _id: "$receiverDistrict",
                        parcelCount: { $sum: 1 },
                        earnings: { $sum: { $toDouble: { $ifNull: [ "$cost", 0 ] } } }
                    }
                }
            ];
            const result = await parcelsCollection.aggregate(pipeline).toArray();
            res.send(result);
        });

        // Rider stats dashboard endpoint
        app.get('/riders/stats', verifyFBToken, verifyRider, async (req, res) => {
            const email = req.decoded_email;
            const riderInfo = await ridersCollection.findOne({ email });
            const earnings = riderInfo?.earnings || 0;

            const parcelsToPickUp = await parcelsCollection.countDocuments({
                pickupRider: email,
                deliveryStatus: 'ready-to-pickup'
            });

            const parcelsToDeliver = await parcelsCollection.countDocuments({
                deliveryRider: email,
                deliveryStatus: 'ready-for-delivery'
            });

            res.send({
                earnings,
                parcelsToPickUp,
                parcelsToDeliver
            });
        });

        // Rider profile fetch endpoint
        app.get('/riders/my-profile', verifyFBToken, async (req, res) => {
            const email = req.decoded_email;
            const rider = await ridersCollection.findOne({ email });
            res.send(rider || {});
        });

        // Rider profile update endpoint
        app.patch('/riders/profile', verifyFBToken, async (req, res) => {
            const email = req.decoded_email;
            const updateData = req.body;
            const query = { email };
            const update = {
                $set: {
                    name: updateData.name,
                    contact: updateData.contact,
                    district: updateData.district
                }
            };
            const result = await ridersCollection.updateOne(query, update, { upsert: true });
            res.send(result);
        });

        // Rider active tasks endpoint
        app.get('/trackings/rider/current-tasks', verifyFBToken, verifyRider, async (req, res) => {
            const email = req.decoded_email;
            const query = {
                $or: [
                    { pickupRider: email, deliveryStatus: 'ready-to-pickup' },
                    { deliveryRider: email, deliveryStatus: 'ready-for-delivery' }
                ]
            };
            const tasks = await parcelsCollection.find(query).toArray();
            res.send(tasks);
        });

        // Admin assigns rider for pickup
        app.patch('/parcels/:id/assign-pickup', verifyFBToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const { riderEmail, trackingId } = req.body;
            const query = { _id: new ObjectId(id) };
            const update = {
                $set: {
                    pickupRider: riderEmail,
                    deliveryStatus: 'ready-to-pickup'
                }
            };
            const result = await parcelsCollection.updateOne(query, update);
            await logTracking(trackingId, 'ready-to-pickup');
            res.send(result);
        });

        // Admin confirms received at service center
        app.patch('/parcels/:id/confirm-received', verifyFBToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const { trackingId } = req.body;
            const query = { _id: new ObjectId(id) };
            const update = {
                $set: {
                    deliveryStatus: 'reached-service-center'
                }
            };
            const result = await parcelsCollection.updateOne(query, update);
            await logTracking(trackingId, 'reached-service-center');
            res.send(result);
        });

        // Admin ships parcel to destination service center
        app.patch('/parcels/:id/ship', verifyFBToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const { trackingId } = req.body;
            const query = { _id: new ObjectId(id) };
            const update = {
                $set: {
                    deliveryStatus: 'shipped'
                }
            };
            const result = await parcelsCollection.updateOne(query, update);
            await logTracking(trackingId, 'shipped');
            res.send(result);
        });

        // Admin assigns rider for delivery
        app.patch('/parcels/:id/assign-delivery', verifyFBToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const { riderEmail, trackingId } = req.body;
            const query = { _id: new ObjectId(id) };
            const update = {
                $set: {
                    deliveryRider: riderEmail,
                    deliveryStatus: 'ready-for-delivery'
                }
            };
            const result = await parcelsCollection.updateOne(query, update);
            await logTracking(trackingId, 'ready-for-delivery');
            res.send(result);
        });

        // Rider confirms pickup transition
        app.patch('/parcels/:id/rider-confirm-pickup', verifyFBToken, verifyRider, async (req, res) => {
            const id = req.params.id;
            const { trackingId } = req.body;
            const email = req.decoded_email;

            const query = { _id: new ObjectId(id), trackingId };
            const parcel = await parcelsCollection.findOne(query);
            if (!parcel) {
                return res.status(404).send({ message: 'parcel not found or tracking mismatch' });
            }

            const nextStatus = (parcel.senderDistrict === parcel.receiverDistrict) 
                ? 'ready-for-delivery' 
                : 'in-transit';

            const update = {
                $set: {
                    deliveryStatus: nextStatus
                }
            };
            const result = await parcelsCollection.updateOne(query, update);

            // Increase rider earnings by 20
            await ridersCollection.updateOne(
                { email },
                { $inc: { earnings: 20 } },
                { upsert: true }
            );

            await logTracking(trackingId, nextStatus);
            res.send(result);
        });

        // Rider confirms delivery transition
        app.patch('/parcels/:id/rider-confirm-delivery', verifyFBToken, verifyRider, async (req, res) => {
            const id = req.params.id;
            const { trackingId } = req.body;
            const email = req.decoded_email;

            const query = { _id: new ObjectId(id), trackingId };
            const parcel = await parcelsCollection.findOne(query);
            if (!parcel) {
                return res.status(404).send({ message: 'parcel not found or tracking mismatch' });
            }

            const update = {
                $set: {
                    deliveryStatus: 'delivered'
                }
            };
            const result = await parcelsCollection.updateOne(query, update);

            // Increase rider earnings by 20
            await ridersCollection.updateOne(
                { email },
                { $inc: { earnings: 20 } },
                { upsert: true }
            );

            await logTracking(trackingId, 'delivered');
            res.send(result);
        });

        // Send a ping to confirm a successful connection
        // await client.db("admin").command({ ping: 1 });
        // console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);

app.get('/', (req, res) => {
    res.send('zap is shifting shifting!')
})

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})

module.exports = app;

