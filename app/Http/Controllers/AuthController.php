<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\HTTP\Response;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    // Register Code
    public function register(Request $request) {
        $fields = $request->validate([
            'name' => ['required','string','max:255'],
            'email' => ['required','string', 'unique:email','max:255', 'unique:users'],
            'password' => ['required','string','min:8', 'confirmed'],
        ]);
        $user = User::create([
            'name' => $fields['name'],
            'email' => $fields['email'],
            'password' => bcrypt($fields['password']),
        ]);
        $token = $user->createToken('myapptoken')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];
        return response($response, 201);
    }
    
    // Login COde
    public function login(Request $request) {
        $fields = $request->validate([
            'email' => ['required','string', 'email','max:255'],
            'password' => ['required','string','min:8'],
        ]);

        // check email
        $user = User::where('email', $fields['email'])->first();

        //  Check passwod
        if(!$user || !Hash::check($fields['password'], $user->password)){
            return response([
                'message'=>'Wrong password'

            ], 401);
        }

        $token = $user->createToken('myapptoken')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];
        return response($response, 201);
    }

    public function logout (Request $request){
        auth()->user()->tokens()->delete();

        return[
            "message" => "Successfully logged out"
        ];
    }
}
