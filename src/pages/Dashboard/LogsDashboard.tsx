import React, { useEffect, useState } from 'react';
import DefaultLayout from '../../layout/DefaultLayout';
import { DataGrid, GridColDef } from '@mui/x-data-grid';
import { TextField, MenuItem, Select, FormControl, InputLabel, SelectChangeEvent, FormGroup, FormControlLabel, Checkbox, ThemeProvider } from '@mui/material';
import theme from '../../theme'; // Import your custom theme
import './logsstyles.css'; // Import the custom CSS file

interface Log {
    id: number;
    src_ip: string;
    dst_ip: string;
    protocol: string;
    malicious: boolean;
    confidence: number;
    timestamp: string;
}

const LogsDashboard: React.FC = () => {
    const [logs, setLogs] = useState<Log[]>([]);
    const [page, setPage] = useState(0);
    const [pageSize, setPageSize] = useState(10);
    const [search, setSearch] = useState('');
    const [totalLogs, setTotalLogs] = useState(0);
    const [searchColumns, setSearchColumns] = useState<string[]>(['src_ip', 'dst_ip']);

    useEffect(() => {
        async function fetchLogs() {
            const response = await window.electron.fetchPacketLogs({ page: page + 1, pageSize, search, searchColumns });
            setLogs(response.logs);
            setTotalLogs(response.total);
        }
        fetchLogs();
    }, [page, pageSize, search, searchColumns]);

    const columns: GridColDef[] = [
        { field: 'id', headerName: 'ID', width: 70 },
        { field: 'src_ip', headerName: 'Source IP', width: 130 },
        { field: 'dst_ip', headerName: 'Destination IP', width: 130 },
        { field: 'protocol', headerName: 'Protocol', width: 130 },
        { field: 'malicious', headerName: 'Malicious', width: 130 },
        { field: 'confidence', headerName: 'Confidence', width: 130 },
        { field: 'timestamp', headerName: 'Timestamp', width: 200 },
    ];

    const handlePageSizeChange = (event: SelectChangeEvent<number>) => {
        setPageSize(Number(event.target.value));
        setPage(0); // Reset page to 0 when page size changes
    };

    const handlePageChange = (params: any) => {
        setPage(params.page);
    };

    const handleCheckboxChange = (event: React.ChangeEvent<HTMLInputElement>) => {
        const { name, checked } = event.target;
        setSearchColumns((prev) => {
            if (checked) {
                return [...prev, name];
            } else {
                return prev.filter((column) => column !== name);
            }
        });
    };

    return (
        <ThemeProvider theme={theme}>
            <DefaultLayout>
                <div className="search-container">
                    <TextField
                        label="Search"
                        variant="outlined"
                        fullWidth
                        onChange={(e) => setSearch(e.target.value)}
                        style={{ marginBottom: '20px' }}
                    />
                </div>
                <div className="search-columns-container">
                    <FormGroup row>
                        {columns.map((col) => (
                            <FormControlLabel
                                control={
                                    <Checkbox
                                        checked={searchColumns.includes(col.field)}
                                        onChange={handleCheckboxChange}
                                        name={col.field}
                                        color="primary"
                                    />
                                }
                                label={col.headerName}
                                key={col.field}
                            />
                        ))}
                    </FormGroup>
                </div>
                <div className="pagination-container">
                    <FormControl variant="outlined" className="page-size-select">
                        <InputLabel id="page-size-label">Page Size</InputLabel>
                        <Select
                            labelId="page-size-label"
                            value={pageSize}
                            onChange={handlePageSizeChange}
                            label="Page Size"
                        >
                            <MenuItem value={10}>10</MenuItem>
                            <MenuItem value={25}>25</MenuItem>
                            <MenuItem value={50}>50</MenuItem>
                        </Select>
                    </FormControl>
                </div>
                <div className="data-grid-container">
                    <DataGrid
                        rows={logs}
                        columns={columns}
                        pageSize={pageSize}
                        rowsPerPageOptions={[10, 25, 50]}
                        paginationMode="server"
                        rowCount={totalLogs}
                        pagination
                        onPageChange={handlePageChange}
                        onPageSizeChange={(params: any) => setPageSize(params.pageSize)}
                        page={page}
                        className="data-grid"
                    />
                </div>
            </DefaultLayout>
        </ThemeProvider>
    );
};

export default LogsDashboard;
