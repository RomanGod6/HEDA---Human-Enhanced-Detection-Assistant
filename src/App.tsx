// App.js
import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { AuthProvider } from './AuthContext';
import PrivateRoute from './PrivateRoute';
import PublicRoute from './PublicRoute';
import Dashboard from './pages/Dashboard/Firewall';
import SignIn from './pages/Authentication/SignIn';
import SignUp from './pages/Authentication/SignUp';

function App() {
  return (

    <Router>
      <AuthProvider>
        <Routes>
          <Route path="/" element={<PrivateRoute><Dashboard /></PrivateRoute>} />
          <Route path="/auth/signin" element={<PublicRoute><SignIn /></PublicRoute>} />
          <Route path="/auth/signup" element={<PublicRoute><SignUp /></PublicRoute>} />
        </Routes>
      </AuthProvider>
    </Router>

  );
}

export default App;
