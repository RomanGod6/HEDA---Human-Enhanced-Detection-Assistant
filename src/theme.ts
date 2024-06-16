// src/theme.js
import { createTheme } from '@mui/material/styles';

const theme = createTheme({
    palette: {
        primary: {
            main: '#1E3A8A', // Adjust to your primary color
        },
        secondary: {
            main: '#D1D5DB', // Adjust to your secondary color
        },
        background: {
            default: '#1E293B', // Adjust to your background color
        },
        text: {
            primary: '#FFFFFF', // Adjust to your text color
        },
    },
    components: {
        MuiDataGrid: {
            styleOverrides: {
                root: {
                    backgroundColor: '#1E293B',
                    color: '#FFFFFF',
                    border: 'none',
                },
                cell: {
                    borderBottom: '1px solid #2D3748',
                },
                columnHeaders: {
                    backgroundColor: '#2D3748',
                    color: '#FFFFFF',
                    borderBottom: '1px solid #2D3748',
                },
                columnHeaderTitle: {
                    fontWeight: 'bold',
                },
                row: {
                    '&:nth-of-type(odd)': {
                        backgroundColor: '#2D3748',
                    },
                    '&:hover': {
                        backgroundColor: '#3B4252',
                    },
                },
                menu: {
                    '& .MuiPaper-root': {
                        backgroundColor: '#1E293B', // Background color of the menu
                        color: '#FFFFFF', // Text color of the menu items
                    },
                },
            },
        },
        MuiMenuItem: {
            styleOverrides: {
                root: {
                    color: '#FFFFFF', // Text color of the menu items
                },
            },
        },
    },
});

export default theme;
