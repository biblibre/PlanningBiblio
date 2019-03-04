<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use PlanningBiblio\LegacyCodeChecker;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\PhpBridgeSessionStorage;

class DefaultController extends Controller
{
    public function index(Request $request)
    {
        ob_start();

        $page = $request->query->get('page');
        $session = $this->get('session');
        $login_id = $session->get('login_id');

        foreach (array('login_id', 'login_nom', 'login_prenom') as $name) {
            if ($session->has($name)) {
                $_SESSION[$name] = $session->get($name);
            }
        }

        include_once('init.php');
        include_once('init_menu.php');
        include_once('init_templates.php');

        require_once('include/feries.php');
        require_once('plugins/plugins.php');
        if (isset($login_id)) {
            require_once('include/cron.php');
        }

        // Si pas de session, redirection vers la page d'authentification
        if (empty($login_id)) {
            // Action executée dans un popup alors que la session a été perdue, on affiche
            if (!$show_menu) {
                echo "<div style='margin:60px 30px;'>\n";
                echo "<center>\n";
                echo "Votre session a expiré.<br/><br/>\n";
                echo "<a href='authentification.php' target='_top'>Cliquez ici pour vous reconnecter</a>\n";
                echo "<center></div>\n";

                return new Response(ob_get_clean());
            } else {
                // Session perdue, on affiche la page d'authentification
                return $this->redirectToRoute('authenticate');
            }
        }

        # Start using twigized script
        $checker = new LegacyCodeChecker();
        if ($checker->isTwigized($page)) {
            include('./'.$page);

            return new Response(ob_get_clean());
        }

        include('./include/header.php');
        if ($show_menu) {
            include('./include/menu.php');
        }

        // Sécurité CSRFToken
        echo <<<EOD
        <form name='CSRFForm' action='#' method='get'>
        <input type='hidden' name='CSRFSession' id='CSRFSession' value='$CSRFSession' />
        </form>
EOD;

        if ($content_planning) {
            echo "<div id='content-planning'>\n";
        } else {
            echo "<div id='content'>\n";
        }

        if ($authorized) {
            include('./' . $page);
        } else {
            echo "<div id='acces_refuse'>Accès refusé</div>\n";
        }
        if ($show_menu) {
            include('./include/footer.php');
        }

        return new Response(ob_get_clean());
    }

    public function authenticate(Request $request)
    {
        ob_start();

        $session = $this->get('session');

        // Initialisation des variables
        $version="2.8.04";

        // Redirection vers setup si le fichier config est absent
        if (!file_exists("include/config.php")) {
            include "include/noConfig.php";
        }

        require_once "include/config.php";
        require_once "include/sanitize.php";

        // IP Blocker : Affiche accès refusé, IP bloquée si 5 tentatives infructueuses lors les 10 dernières minutes
        $IPBlocker=loginFailedWait();
        if ($IPBlocker>0) {
            include "include/accessDenied.php";

            return new Response(ob_get_clean());
        }

        $newLogin=filter_input(INPUT_GET, "newlogin", FILTER_SANITIZE_STRING);
        if (!isset($redirURL)) {
            $redirURL=isset($_REQUEST['redirURL'])?stripslashes($_REQUEST['redirURL']):"index.php";
        }
        $redirURL=filter_var($redirURL, FILTER_SANITIZE_URL);

        $page=null;
        $auth=null;
        $authArgs=null;

        if (!array_key_exists("oups", $_SESSION)) {
            $_SESSION['oups']=array("week"=>false);
        }

        // Authentification CAS
        include_once "ldap/authCAS.php";

        include "plugins/plugins.php";
        include "include/header.php";

        echo "<div id='content-auth'>\n";

        //	Vérification du login et du mot de passe
        if (isset($_POST['login'])) {
            $login=filter_input(INPUT_POST, "login", FILTER_SANITIZE_STRING);
            $password=filter_input(INPUT_POST, "password", FILTER_UNSAFE_RAW);

            include "ldap/auth.php";

            if ($config['Auth-Mode']=="SQL" or $login=="admin") {
                $auth=authSQL($login, $password);
            }

            if ($authArgs and $redirURL) {
                $authArgs.="&amp;redirURL=".urlencode($redirURL);
            } elseif ($redirURL) {
                $authArgs="?redirURL=".urlencode($redirURL);
            }

            // Génération d'un CSRF Token
            $CSRFToken = CSRFToken();
            $_SESSION['oups']['CSRFToken'] = $CSRFToken;

            if ($auth) {
                // Log le login et l'IP du client en cas de succès, pour information
                loginSuccess($login, $CSRFToken);
                $db=new \db();
                $db->select2("personnel", "id,nom,prenom", array("login"=>$login));
                if ($db->result) {
                    $session->set('login_id', $db->result[0]['id']);
                    $session->set('login_nom', $db->result[0]['nom']);
                    $session->set('login_prenom', $db->result[0]['prenom']);
              
                    $db=new \db();
                    $db->CSRFToken = $CSRFToken;
                    $db->update("personnel", array("last_login"=>date("Y-m-d H:i:s")), array("id"=>$session->get('login_id')));
                    echo "<script type='text/JavaScript'>document.location.href='$redirURL';</script>";
                } else {
                    echo "<div style='text-align:center'>\n";
                    echo "<br/><br/><h3 style='color:red'>L'utilisateur n'existe pas dans le planning</h3>\n";
                    echo "<br/><a href='authentification.php{$authArgs}'>Re-essayer</a>\n";
                    echo "</div>\n";
                }
            } else {
                // Log le login tenté et l'IP du client en cas d'echec, pour bloquer l'IP si trop de tentatives infructueuses
                loginFailed($login, $CSRFToken);

                // Si la limite est atteinte, on affiche directement la page "Accès refusé"
                if (loginFailedWait()>0) {
                    echo "<script type='text/JavaScript'>document.location.reload();</script>\n";

                    return new Response(ob_get_clean());
                }

                echo <<<EOD
            <div id='auth'>
            <center><div id='auth-logo'></div></center>
            <h1 id='title'>{$config['Affichage-titre']}</h1>
            <h2 id='h2-planning-authentification'>Planning - Authentification</h2>
            <h2 id='h2-authentification'>Authentification</h2>
            <div style='text-align:center'>
            <h3 style='color:red'>Erreur lors de l'authentification</h3>
            <br/><a href='authentification.php{$authArgs}'>Re-essayer</a>
            </div>
            </div>
EOD;
            }
        } elseif (isset($_GET['acces'])) {
            if (!isset($_GET['no_menu'])) {
                include "include/menu.php";
                echo "<div id='acces_refuse'>Accès refusé</div>\n";
            }
        } elseif (array_key_exists("login_id", $_SESSION)) {		//		logout
            include "ldap/logoutCAS.php";

            session_destroy();
            echo "<script type='text/JavaScript'>location.href='authentification.php{$authArgs}';</script>";
        } else {		//		Formulaire d'authentification
            echo <<<EOD
            <div id='auth'>
            <center><div id='auth-logo'></div></center>
            <h1 id='title'>{$config['Affichage-titre']}</h1>
            <h2 id='h2-planning-authentification'>Planning - Authentification</h2>
            <h2 id='h2-authentification'>Authentification</h2>
            <form name='form' method='post' action='authentification.php'>
            <input type='hidden' name='auth' value='' />
            <input type='hidden' name='redirURL' value='$redirURL' />
            <table style='width:100%;'>
            <tr><td style='text-align:right;width:48%;'>Utilisateur : </td>
            <td><input type='text' name='login' value='$newLogin' /></td></tr>
            <tr><td align='right'>Mot de passe : </td>
            <td><input type='password' name='password' /></td></tr>
            <tr><td colspan='2' align='center'><br/><input type='submit' class='ui-button' value='Valider' /></td></tr>
EOD;
            if ($config['Auth-Anonyme']) {
                echo "<tr><td colspan='2' align='center'><br/><a href='index.php?login=anonyme'>Accès anonyme</a></td></tr>\n";
            }
            echo <<<EOD
            </table>
            <input type='hidden' name='width' />
            </form></div>
EOD;
        }

        include "include/footer.php";

        return new Response(ob_get_clean());
    }
}
