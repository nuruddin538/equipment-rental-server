# Equipora – Equipment Rental Platform (Backend)

Equipora Backend is a RESTful API built with Node.js, Express.js, MongoDB, and Stripe. It powers the Equipora equipment rental platform by handling authentication, equipment management, booking operations, payment processing, and dashboard analytics.

The backend provides secure API endpoints for customers, equipment owners, and administrators with role-based authorization and JWT verification.

## 🌐 Live Demo

🔗 [Frontend Live Site](https://impactora-frontend.vercel.app/)
🔗 [Backend Live Site](https://impactora-backend.vercel.app/)

## 📂 Github Repository

🔗[Frontend Github Repository](https://github.com/nuruddin538/equipment-rental-client)
🔗[Backend Github Repository](https://github.com/nuruddin538/equipment-rental-server)

## 📌 Project Overview

The Equipora backend is responsible for managing the core business logic of the equipment rental platform.

It provides REST APIs that allow customers to browse equipment, create bookings, make payments, and manage their rental activities.

Equipment owners can create and manage equipment listings, monitor customer bookings, and analyze their earnings.

Administrators can manage users, review equipment listings, monitor bookings, and access platform-wide analytics.

## ✨ Key Features

### 🔐 Authentication & Authorization

- JWT token verification.
- Better Auth integration.
- Secure API access.
- Role-based authorization.
- Customer, Owner, and Admin permissions.
- Protected API endpoints.

### 🛠️ Equipment Management

- Create equipment listings.
- Retrieve all available equipment.
- Retrieve equipment details by ID.
- Update equipment information.
- Delete equipment listings.
- Manage equipment availability.
- Manage equipment approval status.
- Retrieve equipment by owner.

### 📅 Booking Management

- Create equipment rental bookings.
- Validate equipment availability.
- Calculate rental costs.
- Support rental duration and quantity.
- Retrieve customer bookings.
- Retrieve owner rental requests.
- Update booking status.
- Track completed and pending rentals.

### 💳 Stripe Payment Integration

- Stripe Checkout Session creation.
- USD currency support.
- Server-side payment calculation.
- Payment amount validation.
- Payment record management.
- Payment status tracking.
- Checkout success and cancellation handling.

### ❤️ Favorites Management

- Add equipment to favorites.
- Remove equipment from favorites.
- Retrieve customer favorite equipment.

### 📊 Owner Analytics

- Total listed equipment.
- Completed rentals.
- Total rental earnings.
- Monthly earnings statistics.
- Business performance data.

### 🛡️ Admin Management

- Retrieve all users.
- Manage user information and roles.
- Retrieve all equipment.
- Review pending equipment approvals.
- Monitor platform bookings.
- Track completed rentals.
- Calculate total platform revenue.
- Generate monthly booking statistics.

### ⚡ API Features

- RESTful API architecture.
- MongoDB aggregation pipelines.
- Centralized error handling.
- JSON request and response.
- CORS configuration.
- Secure environment variable management.

## 🧰 Technologies Used

| Technology            | Purpose                       |
| --------------------- | ----------------------------- |
| Node.js               | JavaScript runtime            |
| Express.js            | Backend framework             |
| MongoDB               | Database                      |
| MongoDB Native Driver | Database operations           |
| Better Auth           | Authentication integration    |
| JWT / JOSE            | Token verification            |
| Stripe                | Payment processing            |
| CORS                  | Cross-origin resource sharing |
| Helmet                | HTTP security headers         |
| express-rate-limit    | API rate limiting             |
| dotenv                | Environment configuration     |

## 📂 Project Structure

```text
equipment-rental-server/
│
├── index.js
├── package.json
├── package-lock.json
├── .env.example
├── .gitignore
└── README.md
```

_Note: Update this structure if your backend is organized into separate routes, middleware, controllers, or configuration folders._

## ⚙️ Installation & Setup

### 1. Clone the Repository

```bash
git clone <YOUR_BACKEND_REPOSITORY_URL>
```

### 2. Navigate to the Project

```bash
cd equipment-rental-server
```

### 3. Install Dependencies

```bash
npm install
```

### 4. Configure Environment Variables

Create a `.env` file in the root directory:

```env
PORT=5000

MONGODB_URI=your_mongodb_connection_string
DB_NAME=your_database_name

BETTER_AUTH_URL=http://localhost:3000
CLIENT_URL=http://localhost:3000

STRIPE_SECRET_KEY=sk_test_your_stripe_secret_key
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret

NODE_ENV=development
```

Use the exact authentication environment variable names configured in your Better Auth and JWT verification implementation.

Never commit your `.env` file or expose secret keys publicly.

### 5. Start the Development Server

```bash
npm run dev
```

The backend should run at:

```text
http://localhost:5000
```

## 📜 Available Scripts

| Command       | Description              |
| ------------- | ------------------------ |
| `npm run dev` | Start development server |
| `npm start`   | Start production server  |

_Available scripts depend on your actual `package.json` configuration._

## 🔗 API Endpoints

The following table describes the main API resource groups. Confirm the exact HTTP methods and paths against your implemented routes.

| Module          | Functionality                                      |
| --------------- | -------------------------------------------------- |
| Authentication  | Verify JWT and user roles                          |
| Equipment       | Create, read, update, and delete equipment         |
| Bookings        | Create and manage rental bookings                  |
| Payments        | Create Stripe Checkout sessions and track payments |
| Favorites       | Manage favorite equipment                          |
| Customer        | Retrieve customer booking information              |
| Owner           | Manage owner equipment and rental information      |
| Owner Analytics | Retrieve owner business analytics                  |
| Admin           | Manage users, equipment, and bookings              |
| Admin Analytics | Retrieve platform statistics and revenue           |

### Important Analytics Endpoints

```http
GET /api/admin/analytics
GET /api/owner/rentals
```

_Add the owner analytics endpoint here after confirming its exact route in your backend._

## 💳 Stripe Payment Process

Equipora uses Stripe Checkout to process equipment rental payments in USD.

### Payment Workflow

1. Customer selects equipment and rental details.
2. Frontend sends booking information to the backend.
3. Backend retrieves the equipment price from MongoDB.
4. Backend validates rental duration and requested quantity.
5. Backend calculates the total rental amount.
6. The amount is converted from USD to cents.
7. Backend creates a Stripe Checkout Session.
8. Customer completes payment through Stripe.
9. Payment and booking records are updated based on the payment result.

### Example Price Calculation

```js
const unitPrice = 100;
const rentalDays = 5;
const quantity = 3;

const totalAmount = unitPrice * rentalDays * quantity;

const amountInCents = Math.round(totalAmount * 100);

console.log(totalAmount); // 1500 USD
console.log(amountInCents); // 150000 cents
```

The example assumes the equipment price is charged per day. The actual calculation should follow the equipment's configured rental type.

## 🗄️ Database Collections

The backend uses MongoDB collections to store platform data.

| Collection       | Purpose                             |
| ---------------- | ----------------------------------- |
| `users` / `user` | User and authentication information |
| `equipment`      | Equipment listings and availability |
| `bookings`       | Rental booking information          |
| `payments`       | Stripe payment records              |
| `favorites`      | Customer favorite equipment         |

_Collection names should match the actual names configured in your MongoDB connection._

## 🔒 Security & Validation

- JWT-based authentication.
- Role-based API authorization.
- Protected owner and admin routes.
- Server-side booking validation.
- Server-side rental price calculation.
- Stripe secret key stored in environment variables.
- CORS configuration.
- Helmet security headers.
- API rate limiting.
- MongoDB data validation and error handling.

## 🚀 Deployment

The backend can be deployed using Vercel or another Node.js hosting platform.

Before deployment:

1. Configure MongoDB connection settings.
2. Set production environment variables.
3. Configure Better Auth JWT/JWKS verification.
4. Set the production frontend URL in CORS.
5. Configure Stripe production keys.
6. Verify all API endpoints.
7. Test payment and booking workflows.

## 🧪 Testing

Recommended testing checklist:

- Verify authentication and JWT validation.
- Test customer, owner, and admin permissions.
- Test equipment CRUD operations.
- Test booking creation and validation.
- Verify rental price calculations.
- Test Stripe Checkout.
- Verify payment status updates.
- Test owner and admin analytics endpoints.

## 👨‍💻 Developer

**MD. NUR UDDIN**

Next.js Full Stack Web Developer

- GitHub: [nuruddin538](https://github.com/nuruddin538)

## 📄 License

This project is developed for educational and portfolio purposes.
