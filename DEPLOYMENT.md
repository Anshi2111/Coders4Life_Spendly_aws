# Deployment Guide

## GitHub Setup

1. **Initialize Git Repository**:
   ```bash
   git init
   git add .
   git commit -m "Initial commit: Spendly payment API app"
   ```

2. **Create GitHub Repository**:
   - Go to GitHub and create a new repository named `spendly-payment-api`
   - Don't initialize with README (we already have one)

3. **Push to GitHub**:
   ```bash
   git remote add origin https://github.com/YOUR_USERNAME/spendly-payment-api.git
   git branch -M main
   git push -u origin main
   ```

## Render Deployment

### Option 1: Using render.yaml (Recommended)

1. **Connect GitHub Repository**:
   - Go to [Render Dashboard](https://dashboard.render.com)
   - Click "New" → "Blueprint"
   - Connect your GitHub repository
   - Render will automatically detect the `render.yaml` file

2. **Environment Variables** (Auto-configured via render.yaml):
   - `NODE_ENV`: production
   - `JWT_SECRET`: Auto-generated secure key
   - `CORS_ORIGIN`: Auto-linked to frontend URL
   - `VITE_API_URL`: Auto-linked to backend URL

### Option 2: Manual Setup

#### Backend Service
1. **Create Web Service**:
   - Service Type: Web Service
   - Connect your GitHub repo
   - Root Directory: `server`
   - Environment: Node
   - Build Command: `npm install`
   - Start Command: `npm start`

2. **Environment Variables**:
   ```
   NODE_ENV=production
   PORT=10000
   JWT_SECRET=your-super-secure-production-secret-key-here
   DB_PATH=./database.sqlite
   CORS_ORIGIN=https://your-frontend-url.onrender.com
   ```

#### Frontend Service
1. **Create Static Site**:
   - Service Type: Static Site
   - Connect your GitHub repo
   - Root Directory: `client`
   - Build Command: `npm install && npm run build`
   - Publish Directory: `dist`

2. **Environment Variables**:
   ```
   VITE_API_URL=https://your-backend-url.onrender.com
   ```

## Post-Deployment Steps

1. **Test the Application**:
   - Visit your frontend URL
   - Test user registration/login
   - Verify API connectivity
   - Test UPI payment flow (with small amounts)

2. **Update README**:
   - Add live demo links
   - Update API documentation with production URLs

3. **Monitor Performance**:
   - Check Render logs for any errors
   - Monitor response times
   - Set up error tracking if needed

## Production Environment Variables

### Backend (.env for local development)
```env
NODE_ENV=production
PORT=10000
JWT_SECRET=your-super-secure-production-secret-key-minimum-32-characters
DB_PATH=./database.sqlite
CORS_ORIGIN=https://your-frontend-domain.onrender.com
```

### Frontend (.env for local development)
```env
VITE_API_URL=https://your-backend-domain.onrender.com
```

## Security Checklist

- [ ] JWT_SECRET is strong and unique (minimum 32 characters)
- [ ] CORS_ORIGIN is set to your exact frontend domain
- [ ] No sensitive data in environment variables
- [ ] HTTPS is enabled (automatic on Render)
- [ ] Database file permissions are correct

## Troubleshooting

### Common Issues

**Build Failures**:
- Check Node.js version compatibility
- Verify all dependencies are in package.json
- Check build logs for specific errors

**CORS Errors**:
- Ensure CORS_ORIGIN matches your frontend URL exactly
- Include protocol (https://) in the URL

**Database Issues**:
- SQLite file will be created automatically
- Check file permissions in deployment logs

**Environment Variable Issues**:
- Verify all required variables are set
- Check for typos in variable names
- Ensure frontend can reach backend URL

### Debug Commands

```bash
# Check if backend is responding
curl https://your-backend-url.onrender.com/health

# Check environment variables (in Render shell)
echo $NODE_ENV
echo $CORS_ORIGIN
```

## Scaling Considerations

- **Database**: Consider PostgreSQL for production scale
- **File Storage**: Use cloud storage for user uploads
- **Caching**: Implement Redis for session management
- **Monitoring**: Add application monitoring tools
- **Backup**: Set up automated database backups

## Cost Optimization

- **Free Tier Limits**: 
  - 750 hours/month for web services
  - 100GB bandwidth/month
  - Services sleep after 15 minutes of inactivity

- **Keep Services Active**:
  - Use uptime monitoring services
  - Implement health check endpoints
  - Consider upgrading to paid plans for production

## Support

For deployment issues:
1. Check Render documentation
2. Review deployment logs
3. Test locally first
4. Check GitHub repository settings