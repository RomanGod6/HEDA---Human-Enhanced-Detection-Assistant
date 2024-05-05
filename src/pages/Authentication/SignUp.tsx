import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios'; // Ensure axios is installed or install it via npm
import Breadcrumb from '../../components/Breadcrumbs/Breadcrumb';
import LogoDark from '../../images/logo/logo-dark.svg';
import Logo from '../../images/logo/logo.svg';
import DefaultLayout from '../../layout/DefaultLayout';

const SignUp = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
    confirmPassword: ''
  });

  const { name, email, password, confirmPassword } = formData;

  const onChange = e => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const onSubmit = async e => {
    e.preventDefault();
    if (password !== confirmPassword) {
      alert('Passwords do not match');
    } else {
      try {
        const config = {
          headers: {
            'Content-Type': 'application/json'
          }
        };

        const body = JSON.stringify({ name, email, password });

        const response = await axios.post('http://198.244.177.53:5000/register', body, config);

        console.log(response.data); // Success response handling
        alert('Account created successfully!');
      } catch (err) {
        console.error(err.response.data); // Error handling
        alert('Error in registration');
      }
    }
  };

  return (
    <DefaultLayout>
      <Breadcrumb pageName="Sign Up" />
      <div className="rounded-sm border border-stroke bg-white shadow-default dark:border-strokedark dark:bg-boxdark">
        <div className="flex flex-wrap items-center">
          {/* Left side with graphic or additional info */}
          <div className="hidden w-full xl:block xl:w-1/2">
            <div className="py-17.5 px-26 text-center">
              <Link className="mb-5.5 inline-block" to="/">
                <img className="hidden dark:block" src={Logo} alt="Logo" />
                <img className="dark:hidden" src={LogoDark} alt="Logo" />
              </Link>
              <p className="2xl:px-20">Lorem ipsum dolor sit amet, consectetur adipiscing elit suspendisse.</p>
            </div>
          </div>
          {/* Right side with form */}
          <div className="w-full xl:w-1/2 xl:border-l-2">
            <div className="w-full p-4 sm:p-12.5 xl:p-17.5">
              <h2 className="mb-9 text-2xl font-bold text-black dark:text-white sm:text-title-xl2">Sign Up to TailAdmin</h2>
              <form onSubmit={onSubmit}>
                {/* Name field */}
                <div className="mb-4">
                  <label className="block font-medium text-black dark:text-white">Name</label>
                  <input
                    type="text"
                    name="name"
                    value={name}
                    onChange={onChange}
                    placeholder="Enter your full name"
                    required
                    className="w-full rounded-lg border py-4 pl-6 pr-10 outline-none focus:border-primary"
                  />
                </div>
                {/* Email field */}
                <div className="mb-4">
                  <label className="block font-medium text-black dark:text-white">Email</label>
                  <input
                    type="email"
                    name="email"
                    value={email}
                    onChange={onChange}
                    placeholder="Enter your email"
                    required
                    className="w-full rounded-lg border py-4 pl-6 pr-10 outline-none focus:border-primary"
                  />
                </div>
                {/* Password field */}
                <div className="mb-4">
                  <label className="block font-medium text-black dark:text-white">Password</label>
                  <input
                    type="password"
                    name="password"
                    value={password}
                    onChange={onChange}
                    placeholder="Enter your password"
                    required
                    className="w-full rounded-lg border py-4 pl-6 pr-10 outline-none focus:border-primary"
                  />
                </div>
                {/* Confirm Password field */}
                <div className="mb-6">
                  <label className="block font-mediumtext-black dark:text-white">Re-type Password</label>
                  <input
                    type="password"
                    name="confirmPassword"
                    value={confirmPassword}
                    onChange={onChange}
                    placeholder="Re-enter your password"
                    required
                    className="w-full rounded-lg border py-4 pl-6 pr-10 outline-none focus:border-primary"
                  />
                </div>
                {/* Submit button */}
                <div className="mb-5">
                  <input
                    type="submit"
                    value="Create account"
                    className="w-full cursor-pointer rounded-lg border border-primary bg-primary p-4 text-white transition hover:bg-opacity-90"
                  />
                </div>
              </form>
              <button className="flex w-full items-center justify-center gap-3.5 rounded-lg border border-stroke bg-gray p-4 hover:bg-opacity-50 dark:border-strokedark dark:bg-meta-4 dark:hover:bg-opacity-50">
                <span>
                  <svg
                    width="20"
                    height="20"
                    viewBox="0 0 20 20"
                    fill="none"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    {/* Google SVG icon code */}
                  </svg>
                </span>
                Sign up with Google
              </button>
              <div className="mt-6 text-center">
                <p>
                  Already have an account? <Link to="/auth/signin" className="text-primary">Sign in</Link>
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </DefaultLayout>
  );
};

export default SignUp;
