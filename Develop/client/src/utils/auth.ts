import { JwtPayload, jwtDecode } from 'jwt-decode';

class AuthService {
  getProfile() {
    // TODO: return the decoded token
    const token = this.getToken();
    if (!token) {
      return null;
    }
    try {
      const decoded: JwtPayload = jwtDecode(token);
      return decoded;
    }
    catch (error) {
      console.error("Failed to decode token:", error);
      return null;
    }
    
  }

  loggedIn() {
    // TODO: return a value that indicates if the user is logged in
    const token = this.getToken();
    return !!token && !this.isTokenExpired(token);
    
  }
  
  isTokenExpired(token: string) {
    // TODO: return a value that indicates if the token is expired
    try {
      const decoded: JwtPayload = jwtDecode(token);
      if (!decoded.exp) {
        return true; // No expiration time means the token is invalid
      }
      const currentTime = Math.floor(Date.now() / 1000); // Current time in seconds
      return decoded.exp < currentTime; // Check if the token is expired
    } catch (error) {
      console.error("Failed to decode token:", error);
      return true; // If decoding fails, consider the token expired
    }
  }

  getToken(): string {
    // TODO: return the token
    return localStorage.getItem('token') || '';
  }

  login(idToken: string) {
    // TODO: set the token to localStorage
    localStorage.setItem('token', idToken);
    // TODO: redirect to the home page
    window.location.href = '/';
  }

  logout() {
    // TODO: remove the token from localStorage
    localStorage.removeItem('token');
    // TODO: redirect to the login page
    window.location.href = '/login';
  }
}

export default new AuthService();