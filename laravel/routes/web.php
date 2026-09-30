<?php

use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return response()->json([
        'status' => 'success',
        'message' => 'Servicio Backend Laravel activo',
        'timestamp' => now()->toDateTimeString()
    ]);
});
