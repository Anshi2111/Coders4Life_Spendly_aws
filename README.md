# Spendly - Personal Finance App for India

A production-ready personal finance management application with real UPI payment integration, built specifically for Indian users.

## 🚀 Features

### Core Functionality
- **User Authentication**: Secure email/password login and registration
- **Salary Management**: Set monthly salary and automatically allocate to categories
- **Dynamic Categories**: Create custom spending categories with percentage or fixed amounts
- **Real UPI Payments**: Integrate with Google Pay, PhonePe, Paytm, and other UPI apps
- **QR Code Scanner**: Scan merchant QR codes for quick payments
- **Transaction Tracking**: Monitor payment history and status
- **Budget Management**: Track spending against category allocations

### Security & Privacy
- **No Bank Data Storage**: Never stores bank details, UPI PINs, or payment credentials
- **UPI Intent Integration**: Redirects to user's preferred UPI app for secure payments
- **JWT Authentication**: Secure token-based authentication
- **Data Encryption**: All data transmission encrypted with HTTPS

### User Experience
- **Mobile-First Design**: Optimized for mobile devices and Android WebView
- **Dark/Light Mode**: Automatic theme switching with user preference
- **Responsive Layout**: Works seamlessly on desktop, tablet, and mobile
- **Error Handling**: Comprehensive error handling with user-friendly messages
- **Offline Support**: Graceful handling of network issues

## 🛠 Tech Stack

### Frontend
- **React 18** with Vite for fast development
- **Tailwind CSS** for modern, responsive styling
- **React Router v6** for navigation
- **Axios** with 10s timeout and comprehensive error handling
- **html5-qrcode** for QR code scanning
- **Lucide React** for consistent icons

### Backend
- **Node.js** with Express.js
- **SQLite** database for simplicity and portability
- **JWT** for authentication
- **bcryptjs** for password hashing
- **CORS** configured for mobile and tunnel access
- **Rate limiting** and security headers

## 📱 UPI Payment Flow

1. User enters payment details in Spendly
2. App generates UPI intent URL: `upi://pay?pa=merchant@upi&am=100&cu=INR`
3. Device redirects to installed UPI app (Google Pay, PhonePe, etc.)
4. User completes payment in UPI app
5. User returns to Spendly and updates transaction status
6. Category balance is automatically updated

**Security Note**: Spendly never handles actual payments or accesses banking credentials.

## 🚀 Quick Start

### Prerequisites
- Node.js 16+ and npm
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd spendly
   ```

2. **Install dependencies**
   ```bash
   npm run install-all
   ```

3. **Configure environment variables**
   
   Backend (server/.env):
   ```env
   PORT=5000
   NODE_ENV=development
   JWT_SECRET=your-super-secret-jwt-key-change-in-production
   DB_PATH=./database.sqlite
   CORS_ORIGIN=http://localhost:5173
   ```
   
   Frontend (client/.env):
   ```env
   VITE_API_URL=http://localhost:5000
   ```

4. **Start development servers**
   ```bash
   npm run dev
   ```

5. **Access the application**
   - Frontend: http://localhost:5173
   - Backend API: http://localhost:5000
   - Health Check: http://localhost:5000/health

## 🌐 Mobile & Tunnel Access

### For Mobile Testing
1. **Update environment variables**:
   ```env
   # In client/.env
   VITE_API_URL=http://YOUR_LOCAL_IP:5000
   
   # In server/.env
   CORS_ORIGIN=http://YOUR_LOCAL_IP:5173
   ```

2. **Find your local IP**:
   ```bash
   # Windows
   ipconfig
   
   # macOS/Linux
   ifconfig
   ```

3. **Access from mobile**: http://YOUR_LOCAL_IP:5173

### For Tunnel Access (localtunnel, ngrok, etc.)
1. **Install localtunnel**:
   ```bash
   npm install -g localtunnel
   ```

2. **Create tunnels**:
   ```bash
   # Terminal 1: Backend tunnel
   lt --port 5000 --subdomain spendly-api
   
   # Terminal 2: Frontend tunnel  
   lt --port 5173 --subdomain spendly-app
   ```

3. **Update environment variables**:
   ```env
   # In client/.env
   VITE_API_URL=https://spendly-api.loca.lt
   
   # In server/.env
   CORS_ORIGIN=https://spendly-app.loca.lt
   ```

## 📊 API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login

### User Management
- `GET /api/user/profile` - Get user profile
- `PUT /api/user/profile` - Update user profile
- `PUT /api/user/salary` - Update salary

### Categories
- `GET /api/categories` - Get user categories
- `POST /api/categories` - Create category
- `PUT /api/categories/:id` - Update category
- `DELETE /api/categories/:id` - Delete category
- `POST /api/categories/recalculate` - Recalculate balances

### Transactions
- `GET /api/transactions` - Get user transactions
- `POST /api/transactions` - Create transaction (initiate payment)
- `PUT /api/transactions/:id/status` - Update transaction status
- `GET /api/transactions/:id` - Get transaction details

### Health Check
- `GET /health` - Server health status

## 🔧 Configuration

### Backend Configuration (server/.env)
```env
PORT=5000                    # Server port
NODE_ENV=development         # Environment
JWT_SECRET=your-secret-key   # JWT signing key (CHANGE IN PRODUCTION)
DB_PATH=./database.sqlite    # Database file path
CORS_ORIGIN=http://localhost:5173  # Allowed frontend origin
```

### Frontend Configuration (client/.env)
```env
VITE_API_URL=http://localhost:5000  # Backend API URL
```

## 🛡 Security Features

### Backend Security
- **Helmet.js**: Security headers
- **Rate Limiting**: 100 requests per 15 minutes per IP
- **CORS**: Configured for specific origins
- **JWT**: Secure token-based authentication
- **Password Hashing**: bcryptjs with salt rounds
- **Input Validation**: Server-side validation for all inputs

### Frontend Security
- **No Sensitive Data Storage**: Only JWT token in localStorage
- **Request Timeout**: 10-second timeout for all API calls
- **Error Handling**: Network errors handled gracefully
- **XSS Protection**: React's built-in XSS protection

## 📱 Mobile App Preparation

The app is designed to be easily converted to a mobile app:

### Android WebView
- Mobile-first responsive design
- Touch-friendly interface
- Optimized for mobile performance
- UPI intent handling works in WebView

### PWA Features (Future)
- Service worker ready
- Offline capability structure
- App manifest ready
- Push notification ready

## 🚨 Error Handling

### Network Errors
- **Timeout**: 10-second timeout with clear error messages
- **Connection Issues**: "Backend unreachable" with retry options
- **4xx Errors**: User-friendly validation messages
- **5xx Errors**: "Server error" with retry suggestions

### App Stability
- **Error Boundaries**: Catch React errors gracefully
- **Fallback UI**: Never crash, always show recovery options
- **Validation**: Comprehensive input validation
- **Safe Rendering**: No object rendering, optional chaining everywhere

## 📈 Performance

### Frontend Optimization
- **Vite**: Fast development and optimized builds
- **Code Splitting**: Route-based code splitting
- **Lazy Loading**: Components loaded on demand
- **Optimized Images**: Proper image handling

### Backend Optimization
- **Database Indexing**: Optimized SQLite queries
- **Connection Pooling**: Efficient database connections
- **Caching**: Response caching where appropriate
- **Compression**: Gzip compression enabled

## 🧪 Testing

### Manual Testing Checklist
- [ ] User registration and login
- [ ] Salary setup and category creation
- [ ] UPI payment flow (test with small amounts)
- [ ] QR code scanning
- [ ] Transaction status updates
- [ ] Mobile responsiveness
- [ ] Dark/light mode switching
- [ ] Error handling scenarios

### Production Readiness
- [ ] Environment variables configured
- [ ] HTTPS enabled
- [ ] Database backups configured
- [ ] Error monitoring setup
- [ ] Performance monitoring
- [ ] Security headers verified

## 🚀 Deployment

### Quick Deploy to Render

1. **Run the deployment script**:
   ```bash
   # On Windows
   deploy.bat
   
   # On macOS/Linux
   ./deploy.sh
   ```

2. **Deploy on Render**:
   - Go to [Render Dashboard](https://dashboard.render.com)
   - Click "New" → "Blueprint"
   - Connect your GitHub repository
   - Render will auto-deploy using `render.yaml`

### Manual Deployment

See [DEPLOYMENT.md](./DEPLOYMENT.md) for detailed deployment instructions including:
- GitHub setup
- Render configuration
- Environment variables
- Troubleshooting guide

### Production URLs
- **Frontend**: `https://spendly-frontend.onrender.com`
- **Backend API**: `https://spendly-api.onrender.com`
- **Health Check**: `https://spendly-api.onrender.com/health`

## 📄 License

MIT License - see LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📞 Support

For support or questions:
- Create an issue in the repository
- Check the troubleshooting section below

## 🔧 Troubleshooting

### Common Issues

**Backend won't start**:
- Check if port 5000 is available
- Verify environment variables
- Check database permissions

**Frontend can't connect to backend**:
- Verify VITE_API_URL in client/.env
- Check CORS configuration
- Ensure backend is running

**UPI payments not working**:
- Test on actual mobile device
- Verify UPI apps are installed
- Check UPI intent URL format

**Mobile access issues**:
- Update CORS_ORIGIN with your IP
- Use HTTPS for production
- Test with different devices

### Debug Mode
Enable debug logging:
```env
# In server/.env
NODE_ENV=development
```

This will show detailed error messages and request logs.

---

**Built with ❤️ for Indian users by the Spendly team**