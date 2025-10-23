<?php

use App\Http\Controllers\API\AuthController;
use App\Http\Controllers\API\ParteController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::middleware(['auth:sanctum','midread','mid1'])->group( function () {
    Route::get('partes', [ParteController::class,'index'])->middleware('alguna:read,update');
    Route::get('parte/{id}', [ParteController::class,'show'])
        ->middleware(['midread','midmindundi']);
        //->middleware('todas:read,admin');
    Route::post('parte', [ParteController::class,'store'])->middleware(['midadmin']);
    Route::put('parte/{id}', [ParteController::class,'update'])->middleware('midadmin');
    Route::delete('parte/{id}', [ParteController::class,'destroy'])->middleware('midadmin');
});

Route::post('login', [AuthController::class, 'login']);
Route::post('logout', [AuthController::class, 'logout']);
Route::post('register', [AuthController::class, 'register']);

Route::get('/nologin', function () {
    return response()->json(["success"=>false, "message" => "Unauthorised"],203);
});
