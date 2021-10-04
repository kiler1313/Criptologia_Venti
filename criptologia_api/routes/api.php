<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

Route::post('/queryAllUsers','App\Http\Controllers\LoginController@queryAllUsers'); // Muestra todos los usuarios
Route::post('/createUser','App\Http\Controllers\LoginController@createUser'); // Crea los usuarios en el aplicativo
Route::post('/showTokens','App\Http\Controllers\LoginController@showTokens'); // Muestra los tokens registrados
Route::post('/login','App\Http\Controllers\LoginController@login'); // Muestra los tokens registrados
Route::post('/editTokensMaster','App\Http\Controllers\LoginController@editTokensMaster'); // Edita los tokens maestros
Route::post('/editTokenPublic','App\Http\Controllers\LoginController@editTokenPublic'); // Edita el token publico

