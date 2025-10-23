<?php

use App\Http\Middleware\Mid1;
use App\Http\Middleware\MidAdmin;
use App\Http\Middleware\MidDelete;
use App\Http\Middleware\MidMindundi;
use App\Http\Middleware\MidRead;
use App\Http\Middleware\MidUpdate;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\JsonResponse;
use Laravel\Sanctum\Exceptions\MissingAbilityException;
use Laravel\Sanctum\Http\Middleware\CheckAbilities;
use Laravel\Sanctum\Http\Middleware\CheckForAnyAbility;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {

        $middleware->alias([
            'todas' => CheckAbilities::class,
            'alguna' => CheckForAnyAbility::class,
            'mid1' => Mid1::class,
            'midread' => MidRead::class,
            'midupdate' => MidUpdate::class,
            'middelete' => MidDelete::class,
            'midadmin' => MidAdmin::class,
            'midmindundi' => MidMindundi::class
        ]);
        $middleware->redirectGuestsTo('/api/nologin');
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        // $exceptions->render(function (BindingResolutionException $e, $request) {
        //     return new JsonResponse([
        //         'error' => 'Middleware o clase no encontrada.',
        //         'detalle' => $e->getMessage(),
        //     ], 500);
        // });
    })
    ->create();
