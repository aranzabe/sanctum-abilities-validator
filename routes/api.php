<?php

use App\Http\Controllers\API\AuthController;
use App\Http\Controllers\API\ParteController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::middleware('auth:sanctum')->group( function () {
    Route::get('partes', [ParteController::class,'index']);
    Route::post('parte', [ParteController::class,'store']);
    Route::get('parte/{id}', [ParteController::class,'show']);
    Route::put('parte/{id}', [ParteController::class,'update']);
    Route::delete('parte/{id}', [ParteController::class,'destroy']);
});

Route::post('login', [AuthController::class, 'login']);
Route::post('logout', [AuthController::class, 'logout']);
Route::post('register', [AuthController::class, 'register']);

Route::get('/nologin', function () {
    return response()->json(["success"=>false, "message" => "Unauthorised"],203);
});
