<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class MidMindundi
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
         $token = $request->user();
        if ($token->tokenCan("mindundi")) {
           return $next($request);
        }
        else {
            return response()->json(["success"=>false, "message" => "Unauthorised"],404);
        }
    }
}
