<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function login(Request $request)
    {

        $input = $request->all();
        $rules = [
            'email' => 'required|email|max:255',
            'password' => 'required|min:8'
        ];
        $messages = [
            'email' => 'El campo :attribute debe ser un correo electrónico válido.',
            'max' => 'El campo :attribute no debe exceder el tamaño máximo permitido.',
            'min' => 'El campo :attribute debe tener al menos :min caracteres.',
            'required' => 'El campo :attribute es obligatorio.'
        ];

        $validator = Validator::make($input, $rules, $messages);
        if($validator->fails()){
            return response()->json($validator->errors(),422);
        }


        if(Auth::attempt(['email' => $request->email, 'password' => $request->password])){
            $auth = Auth::user();
            // return $auth;
            //$tokenResult = $auth->createToken('LaravelSanctumAuth');
            $tokenResult = $auth->createToken('LaravelSanctumAuth',['read','mindundi']); // Asignar abilities al token

            // Actualizar expiración
            $hours = (int) env('SANCTUM_EXPIRATION_HOURS', 2);
            $tokenResult->accessToken->expires_at = now()->addHours($hours);
            $tokenResult->accessToken->save();

            $success = [
                'id'         => $auth->id,
                'name'       => $auth->name,
                'token'      => $tokenResult->plainTextToken,
                'expires_at' => $tokenResult->accessToken->expires_at == null ? null :  $tokenResult->accessToken->expires_at->toDateTimeString()
            ];

            return response()->json(["success"=>true,"data"=>$success, "message" => "User logged-in!"]);
        }
        else{
            return response()->json(["success"=>false, "message" => "Unauthorised"],404);
        }
    }

    public function register(Request $request)
    {
	    // $us = User::where('email',$request->email)->first();
        // if(!empty($us->email)) {
        //     return response()->json(["success"=>false, "message" => "Already registered user"]);
        // }

        $input = $request->all();
        $rules = [
            'name' => 'required|string|max:20',
            'email' => 'required|email|max:255|unique:users',
            'password' => 'required|min:8',
            'confirm_password' => 'required|same:password',
            'edad' => 'required|integer|between:18,190'
        ];
        $messages = [
            'unique' => 'El :attribute ya está registrado en la base de datos.',
            'email' => 'El campo :attribute debe ser un correo electrónico válido.',
            'same' => 'El campo :attribute y :other deben coincidir.',
            'max' => 'El campo :attribute no debe exceder el tamaño máximo permitido.',
            'min' => 'El campo :attribute debe tener al menos :min caracteres.',
            'between' => 'El campo :attribute debe estar entre :min y :max años.',
            'integer' => 'El campo :attribute debe ser un número entero.',
            'required' => 'El campo :attribute es obligatorio.'
        ];

        $validator = Validator::make($request->all(), $rules, $messages);
        if($validator->fails()){
            return response()->json($validator->errors(),422);
        }


        $input['password'] = bcrypt($input['password']);
        $user = User::create($input);

        //$tokenResult = $user->createToken('LaravelSanctumAuth');
        $tokenResult = $user->createToken('LaravelSanctumAuth',['admin','update','delete','read']); //Asignar abilities al token.

        // Actualizar expiración
        // $hours = (int) env('SANCTUM_EXPIRATION_HOURS', 2);
        // $tokenResult->accessToken->expires_at = now()->addHours($hours);
        // $tokenResult->accessToken->save();

        $success = [
            'id' => $user->id,
            'name' => $user->name,
            'token' => $tokenResult->plainTextToken,
            'expires_at' => $tokenResult->accessToken->expires_at ==null ? null:  $tokenResult->accessToken->expires_at->toDateTimeString()
        ];


        return response()->json(["success"=>true,"data"=>$success, "message" => "User successfully registered!"]);
    }

     /**
     * Por defecto los tokens de Sanctum no expiran. Se puede modificar esto añadiendo una cantidad en minutos a la variable 'expiration' en el archivo de config/sanctum.php.
     */
     public function logout(Request $request)
    {
        if(Auth::attempt(['email' => $request->email, 'password' => $request->password])){
            $cantidad = Auth::user()->tokens()->delete();
            return response()->json(["success"=>true, "message" => "Tokens Revoked: ".$cantidad],200);
        }
        else {
            return response()->json(["success"=>false, "message" => "Unauthorised"],404);
        }

    }
}
