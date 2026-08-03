@echo off
echo =========================================
echo   PrinterPartsPoint - Starting Server
echo =========================================
echo.
cd backend
echo Installing packages (first time only)...
npm install
echo.
echo Starting backend server...
npm run dev