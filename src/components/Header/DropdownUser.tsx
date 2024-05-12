import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../AuthContext';

const DropdownUser = () => {
  const { user, setIsLoggedIn } = useAuth();
  const [dropdownOpen, setDropdownOpen] = useState(false);

  const handleLogout = () => {
    localStorage.removeItem('token');
    setIsLoggedIn(false);
  };

  return (
    <div className="relative">
      <div onClick={() => setDropdownOpen(!dropdownOpen)} className="flex items-center gap-4 cursor-pointer">
        <span className="hidden text-right lg:block">
          <span className="block text-sm font-medium text-black dark:text-white">
            {user ? user.name : 'Guest'}
          </span>
          <span className="block text-xs">{user ? user.role : 'No Role'}</span>
        </span>

        <img src={user ? user.avatar : 'Default_Icon.png'} alt="User" className="h-10 w-10 rounded-full" />
      </div>

      {dropdownOpen && (
        <div className="absolute right-0 mt-4 w-48 bg-white shadow-md">
          <ul>
            <li><Link to="/profile">Profile</Link></li>
            <li><button onClick={handleLogout}>Log Out</button></li>
          </ul>
        </div>
      )}
    </div>
  );
};

export default DropdownUser;
