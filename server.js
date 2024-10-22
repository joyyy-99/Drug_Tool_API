require('dotenv').config()
const express = require('express');
const mysql = require('mysql');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const path = require('path');


const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'drug_tool'
});
connection.connect((err) => {
    if (err) {
        console.log('Error connecting to the database.', err);
        return;
    }
    console.log('Database connected successfully!');
});

const app = express();

app.use(session({
    secret:'secret',
    resave: false,
    saveUninitialized: true
}));

let refreshTokens = []

app.use(express.json());

app.listen(3000,()=>{
    console.log("Server listening on 3000")
})


app.post('/register', (req,res)=>{
	connection.query(
		"INSERT INTO `users`(`ID`, `Role`, `Email`, `Gender`, `Password`) VALUES ( ? , ? , ? , ? , ? )",
		[req.body.id, req.body.role, req.body.email, req.body.gender, req.body.password],
		(err)=>{
			if(err) return res.status(500).json({error : "Internal Server Error. User already exists/Error in data entered"})
			return res.status(200).json({message : "New user successfully Registered"})
		}
	)
})


app.post('/login', (req,res)=>{

	if (req.body == null || req.body.id ==null || req.body.role == null || req.body.password ==null ) {
        return res.status(500).json({ message: 'Please fill in all the fields' });
    }

	connection.query(
		"SELECT * FROM `users` WHERE `ID` = ?  AND `Role` = ?",
		[req.body.id, req.body.role],
		(err,results)=>{
			if(err) return res.status(500).json({error : "Internal Server Error."})

			if (results.length === 0) {
				return res.status(401).json({ message: 'No such user exists' });
			}
			
			//console.log(results);
		
			if (req.body.password === results[0].Password) {
				const user = {
					id: results[0].ID,
					role: results[0].Role,
					hasAccessToken: false
				};
			
				req.session.user = user;
				req.session.save(); 

				console.log(req.session.user);
		
				connection.query(
					"UPDATE `users` SET `Login_Time` = CURRENT_TIMESTAMP WHERE `ID` = ? AND `Role` = ?",
					[user.id, user.role],
					(updateError) => {
						if (updateError) {
						console.error('Error updating last login timestamp');
						return res.status(500).json({ message: 'Internal Server Error. Time Update Error' + updateError.stack})
						}
						console.log('Login Successful')
						return res.status(200).json({ message: 'Login successful. Welcome to the API' })
					}
				);
			}else {
				console.log('Password Mismatch');
				return res.status(401).json({ message: 'Invalid credentials' })
			}
		}
	)
})


app.get('/tokens', (req, res) => {
    //To get the access token
      const user = req.session.user;
  
      if (!user) {
          return res.status(401).json({ message: 'Unauthorized. Please Login to get a token' });
      }
      console.log(user);

	  if (user.hasAccessToken) {
		return res.status(400).json({ message: 'Access token already obtained. Use /refresh to get a new one.' });
	  }
  
      const accessToken = generateAccessToken(user)
      const refreshToken = jwt.sign(user.id, process.env.REFRESH_TOKEN_SECRET)
      refreshTokens.push(refreshToken)
      
	  user.hasAccessToken = true;
	  req.session.save(); 

      res.status(200).json({ accessToken: accessToken , refreshToken : refreshToken});
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        return res.status(401).json({ message: 'Authorization Failed. Token Not Available' });
    }

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, userData) => {
        if (err) return res.status(403).json({ message: 'Token verification failed' });
        req.session.user = userData; 
        next();
    });
}


function generateAccessToken(user) {
    const payload = { id: user.id }; 
    return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {expiresIn : '15m'});
}
  
app.post('/refresh', (req,res)=>{
 
  const refreshToken = req.body.token
  if (refreshToken == null) return res.sendStatus(401)
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(401)
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err,user)=>{
      if(err) return res.sendStatus(403)
      const accessToken = generateAccessToken({id : user.id})
      res.json({accessToken : accessToken})
  })

})


app.post('/admin/add-category', (req,res)=>{
	const user = req.session.user
  
    if (!user) {
      return res.status(401).json({ message: 'Unauthorized. Please login for access.' })
    }

	if (user.role != 'admin' || user.role != 'admin' ) {
		return res.status(401).json({message : "Unauthorized. Only administators can access."})
	}

	console.log(`Admin adding category: ${req.body.category}`)
	connection.query(
		"INSERT INTO `categories` (`Drug_Category`) VALUES (?)",
		[req.body.category],
		(err,results)=>{
			if (err) return res.status(500).json({error : "Internal Server error has occured or Drug Category already exists"}) 
			return res.status(200).send({message : "Drug Category added successfully."})
		}
	)
})


app.post('/admin/edit-category', (req,res)=>{
	const user = req.session.user
  
    if (!user) {
      return res.status(401).json({ message: 'Unauthorized. Please login for access.' })
    }

	if (user.role != 'admin' || user.role != 'admin' ) {
		return res.status(401).json({message : "Unauthorized. Only administators can access."})
	}

	console.log(`Admin adding category: ${req.body.previous} to ${req.body.new}`)
	connection.query(
		"UPDATE `categories` SET `Drug_Category` = ? WHERE `Drug_Category`= ?",
		[req.body.new, req.body.previous],
		(err,results)=>{
			if (err) return res.status(500).json({error : "Internal Server error has occured"}) 
			return res.status(200).send({message : "Drug Category edited successfully."})
		}
	)
})


app.post('/admin/add-user', (req,res)=>{
	const user = req.session.user
  
    if (!user) {
      return res.status(401).json({ message: 'Unauthorized. Please login for access.' })
    }

	if (user.role != 'admin' || user.role != 'admin' ) {
		return res.status(401).json({message : "Unauthorized. Only administators can access."})
	}

	console.log(`Admin adding user: ${req.body.id}`)
	connection.query(
		"INSERT INTO `users`(`ID`, `Role`, `Email`, `Gender`, `Password`) VALUES (?,?,?,?,?)",
		[req.body.id, req.body.role, req.body.email, req.body.gender, req.body.password],
		(err,results)=>{
			if (err) return res.status(500).json({error : "Internal Server error has occured or User already exists"}) 
			return res.status(200).send({message : "User added successfully."})
		}
	)
})


app.post('/admin/add-drug', (req,res)=>{
	const user = req.session.user
  
    if (!user) {
      return res.status(401).json({ message: 'Unauthorized. Please login for access.' })
    }

	if (user.role != 'admin' || user.role != 'admin' ) {
		return res.status(401).json({message : "Unauthorized. Only administators can access."})
	}

	console.log(`Admin adding drug: ${req.body.name}`)
	connection.query(
		"INSERT INTO `drugs`(`Drug_ID`, `Drug_Name`, `Drug_Description`, `Drug_Category`, `Drug_Quantity`, `Drug_Expiration_Date`, `Drug_Manufacturing_Date`) VALUES (? ,? ,? ,? ,? ,? ,? )",
		[req.body.id, req.body.name, req.body.description, req.body.category, req.body.quantity, req.body.expiry, req.body.manufactury],
		(err,results)=>{
			if (err) return res.status(500).json({error : "Internal Server error has occured or Error in data entered"}) 
			return res.status(200).send({message : "Drug added successfully."})
		}
	)
})


app.post('/admin/grant-access', (req,res)=>{
	const user = req.session.user
  
    if (!user) {
      return res.status(401).json({ message: 'Unauthorized. Please login for access.' })
    }

	if (user.role != 'admin' || user.role != 'admin' ) {
		return res.status(401).json({message : "Unauthorized. Only administators can access."})
	}

	connection.query(
		"UPDATE `requests` SET `Subscribed`= 'Y' WHERE  `ID`= ? AND `Role`= ? AND `Resource`= ? ",
		[req.body.id, req.body.role, req.body.resource.toUpperCase()],
		(err)=>{
			if (err) return res.status(500).json({error : "Internal Server Error. Could not grant access to product"})
			connection.query(
				`UPDATE subscriptions SET ${req.body.resource.toUpperCase()}='Y'  WHERE  ID = ? AND Role= ? `,
				[req.body.id, req.body.role],
				(Err)=>{
					if (Err) return res.status(401).json({error : "Resource already granted or Resource name inserted incorrectly" + Err.stack})
		
					return res.status(200).json({message : `Subscription is to ${req.body.resource.toUpperCase()} for ${req.body.id} : ${req.body.role} is successful`})
				}
			)
		}
	)
})

app.post('/users/subscribe', (req,res)=>{
	const user = req.session.user
  
    if (!user) {
      return res.status(401).json({ message: 'Unauthorized. Please login for access.' })
    }

	connection.query(
		"SELECT `ID`, `Role`, `Resource`, `Subscribed` FROM `requests` WHERE `ID` = ? AND `Role` = ? AND `Resource` = ? AND `Subscribed` = 'Y' ",
		[req.body.id, req.body.role, req.body.resource.toUpperCase()],
		(err,results)=>{
			if (err) return res.status(500).json({error : "Already subscribed to this resource"})

			connection.query(
				"SELECT `ID`, `Role`, `Resource`, `Subscribed` FROM `requests` WHERE `ID` = ? AND `Role` = ? AND `Resource` = ? AND `Subscribed` = 'N' ",
				[req.body.id, req.body.role, req.body.resource.toUpperCase()],
				(err,results)=>{
					if (err) return res.status(500).json({error : "Internal Server Error"})

					if(results.length > 0) return res.status(200).json({message : "Your subscription is already being processed"})

					connection.query(
						"INSERT INTO `requests`(`ID`, `Role`, `Resource`) VALUES (? ,? ,?)",
						[req.body.id, req.body.role, req.body.resource.toUpperCase()],
						(err)=>{
							if (err) return res.status(500).json({error : "Internal Server Error. Could not subscribe to product"})
							return res.status(200).json({message : "Subscription is being processed"})
						}
					)
				}
			)
		}
	)
})


app.get('/users', authenticateToken, (req,res)=>{
	const user = req.session.user
  
    if (!user) {
      return res.status(401).json({ message: 'Unauthorized. Please login for access.' })
    }

	console.log("GET list of all API users");
	connection.query(
		"SELECT `ID`, `Role`, `Email`, `Gender`, `Login_Time` FROM `users`",
		(err,results)=>{
			if (err) return res.status(500).json("Internal server error. Could not get list of users.")
			return res.status(200).json(results)
		}
	)
})


app.get('/users/id/:id', authenticateToken, (req,res)=>{
	const user = req.session.user
  
    if (!user) {
      return res.status(401).json({ message: 'Unauthorized. Please login for access.' })
    }

	console.log(`GET user with id ${req.params.id}`);
	connection.query(
		"SELECT `ID`, `Role`, `Email`, `Gender`, `Login_Time` FROM `users` WHERE `ID` = ? ",
		[req.params.id],
		(err,results)=>{
			if (err) return res.status(500).json("Internal server error. Could not get user.")
			return res.status(500).json(results)
		}
	)

})


app.get('/users/email/:email', authenticateToken, (req,res)=>{
	const user = req.session.user
  
    if (!user) {
      return res.status(401).json({ message: 'Unauthorized. Please login for access.' })
    }

	console.log(`GET user with email ${req.params.email}`);
	connection.query(
		"SELECT `ID`, `Role`, `Email`, `Gender`, `Login_Time` FROM `users` WHERE `Email` = ? ",
		[req.params.email],
		(err,results)=>{
			if (err) return res.status(500).json("Internal server error. Could not get user.")
			return res.status(500).json(results)
		}
	)
		
})



app.get('/users/gender/:gender', authenticateToken, (req,res)=>{
	const user = req.session.user
  
    if (!user) {
      return res.status(401).json({ message: 'Unauthorized. Please login for access.' })
    }

	console.log(`GET user with gender ${req.params.gender}`);
	connection.query(
		"SELECT `ID`, `Role`, `Email`, `Gender`, `Login_Time` FROM `users` WHERE `Gender` = ? ",
		[req.params.gender],
		(err,results)=>{
			if (err) return res.status(500).json("Internal server error. Could not get user.")
			return res.status(500).json(results)
		}
	)
})


app.get('/users/purchased-drug/:drug', authenticateToken, (req,res)=>{
	const user = req.session.user
  
    if (!user) {
      return res.status(401).json({ message: 'Unauthorized. Please login for access.' })
    }

	console.log(`GET user with drug purchased ${req.params.drug}`);
	connection.query(
		"SELECT u.`ID`, u.`Role`, u.`Email`, u.`Gender`, u.`Login_Time` FROM `users` u INNER JOIN `purchases` p ON p.`ID` = u.`ID` WHERE p.`Drug_ID` = ? ",
		[req.params.drug],
		(err,results)=>{
			if (err) return res.status(500).json("Internal server error. Could not get user.")
			return res.status(500).json(results)
		}
	)

})


app.get('/users/purchased-category/:cat', authenticateToken, (req,res)=>{
	const user = req.session.user
  
    if (!user) {
      return res.status(401).json({ message: 'Unauthorized. Please login for access.' })
    }

	console.log(`GET user with category purchased ${req.params.cat}`);
	connection.query(
		"SELECT u.`ID`, u.`Role`, u.`Email`, u.`Gender`, u.`Login_Time` FROM `users` u INNER JOIN `purchases` p ON p.`ID` = u.`ID` INNER JOIN `drugs` d ON d.Drug_ID =p.Drug_ID WHERE d.`Drug_Category` = ?",
		[req.params.cat],
		(err,results)=>{
			if (err) return res.status(500).json("Internal server error. Could not get user.")
			return res.status(500).json(results)
		}
	)
})

app.get('/users/time', authenticateToken, (req,res)=>{
	const user = req.session.user
  
    if (!user) {
      return res.status(401).json({ message: 'Unauthorized. Please login for access.' })
    }


	console.log(`GET user by descending login time`);
	connection.query(
		"SELECT `ID`, `Role`, `Email`, `Gender`, `Login_Time` FROM `users` ORDER BY  `Login_Time` DESC ",
		(err,results)=>{
			if (err) return res.status(500).json("Internal server error. Could not get users.")
			return res.status(500).json(results)
		}
	)

})



app.get('/drugs', (req,res)=>{
	const user = req.session.user
  
    if (!user) {
      return res.status(401).json({ message: 'Unauthorized. Please login for access.' })
    }

	console.log("GET list of all drugs");
	connection.query(
		"SELECT * FROM `drugs`",
		(err,results)=>{
			if (err) return res.status(500).json("Internal server error. Could not get list of drugs") 
			return res.status(500).json(results)
		}
	)
})


app.get('/drugs/id/:id', (req,res)=>{
	const user = req.session.user
  
    if (!user) {
      return res.status(401).json({ message: 'Unauthorized. Please login for access.' })
    }

	console.log(`GET drug with id ${req.params.id}`);
	connection.query(
		"SELECT * FROM `drugs` WHERE `Drug_ID` = ? ",
		[req.params.id],
		(err,results)=>{
			if (err) return res.status(500).json("Internal server error. Could not get list of drugs") 
			return res.status(500).json(results)
		}
	)
})



app.get('/drugs/category/:cat', (req,res)=>{
	const user = req.session.user
  
    if (!user) {
      return res.status(401).json({ message: 'Unauthorized. Please login for access.' })
    }

	
	console.log(`GET drug with category ${req.params.cat}`);
	connection.query(
		"SELECT * FROM `drugs` WHERE `Drug_Category` = ? ",
		[req.params.cat],
		(err,results)=>{
			if (err) return res.status(500).json("Internal server error. Could not get list of drugs") 
			return res.status(500).json(results)
		}
	)
})


app.get('/drugs/user/:id', authenticateToken, (req,res)=>{
	const user = req.session.user
  
    if (!user) {
      return res.status(401).json({ message: 'Unauthorized. Please login for access.' })
    }

	console.log(`GET drugs used by user ${req.params.id}`)
	connection.query(
		"SELECT d.* FROM `users` u INNER JOIN `purchases` p ON p.`ID` = u.`ID` INNER JOIN `drugs` d ON d.Drug_ID =p.Drug_ID WHERE u.ID = ?",
		[req.params.id],
		(err,results)=>{
			if(err) return res.status(500).json("Internal Server Error. Could not get drugs by user")
			return res.status(200).json(results)
		}
	)
})
