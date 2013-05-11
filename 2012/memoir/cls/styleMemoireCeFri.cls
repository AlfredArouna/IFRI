
\ProvidesFile{styleMemoireCeFri.cls}
\ProvidesClass{cls/styleMemoireCeFri}

%% On charge la classe report
\DeclareOption*{\PassOptionsToClass{\CurrentOption}{report}}
\ProcessOptions
\LoadClass[a4paper,11pt,oneside]{report}

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%  chargement des paquetages     %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\usepackage[T1]{fontenc}
\usepackage{ucs}
\usepackage[utf8x]{inputenc}
\usepackage[french,english]{babel}
\usepackage{setspace}
\usepackage[]{graphicx}
\usepackage{amsmath}
\usepackage{amsfonts}
\usepackage{amssymb} % pour quelques symboles mathmatiques comme <ou=
\usepackage[amssymb,cdot]{SIunits}
\usepackage{mathcomp} % pour avoir le mu droit  $\tcmu$
\usepackage{multirow}
\usepackage{geometry} % pour la mise en page: marge haut, bas, droit et gauche.
\usepackage[Lenny]{fncychap} %personnaliser le titre des chapitres
\usepackage{palatino} % choix de la police
\usepackage{float} % obliger l'image a rester la ou je veux

% activer tous les liens
\usepackage[ 
            colorlinks=true,%activer la coloration des liens 
            linkcolor=RoyalBlue,% personaliser la couleur des liens simple
            %linkcolor=NavyBlue,% personaliser la couleur des liens simple
            ]{hyperref}


\usepackage[nonumberlist,style=altlist]{glossaries}
\renewcommand*{\glsgroupskip}{}
\renewcommand*{\glsseeformat}[3][\seename]{%
(\xmakefirstuc{#1} \glsseelist{#2}.)}
  
			
\usepackage{fancyhdr}
\usepackage{lastpage} % la dernière page
\usepackage{titlesec} % modifification des titres
\usepackage[usenames,dvipsnames,svgnames,table]{xcolor} % les couleurs avec les divers modes d'appels
\usepackage[strict]{changepage} % ajustement automatique de la largeur des frame
\usepackage{framed} % pour definir nos propres frames
\usepackage{listings} % listing de code
\usepackage{listingsutf8} % listing utf8
\usepackage{caption}
\usepackage[francais]{minitoc} % mini table des matières
\usepackage{blindtext}
\usepackage{pifont}
\usepackage{pdflscape} % mettre certaines page en paysage
\usepackage{courier} % pour les listings


% les couleurs du code
\definecolor{javared}{rgb}{0.6,0,0} % for strings
\definecolor{javagreen}{rgb}{0.25,0.5,0.35} % comments
\definecolor{javapurple}{rgb}{0.5,0,0.35} % keywords
\definecolor{javadocblue}{rgb}{0.25,0.35,0.75} % javadoc
\definecolor{lbcolor}{rgb}{0.9,0.9,0.9}  
\lstset{
basicstyle=\ttfamily,
basicstyle=\scriptsize,
upquote=true,
numbers=left,
numberstyle=\tiny\color{black},
stepnumber=1,
numbersep=5pt,
tabsize=2,
showspaces=false,
showstringspaces=false,
extendedchars=true,
backgroundcolor=\color{lbcolor}, 
literate={á}{{\'a}}1 {ã}{{\~a}}1 {é}{{\'e}}1,
frame=leftline
}

\lstdefinestyle{Shell}{delim=[il][\bfseries]{BB}}

\definecolor{gris}{rgb}{68,68,68}
\definecolor{gray}{rgb}{0.5,0.5,0.5}
\definecolor{lgray}{gray}{0.97} % page de garde
\definecolor{bookColor}{cmyk}{0 , 0  , 0   , 0.98}  % 0.90\% of black
\usepackage{multirow} % pour les rowspan des tableaux
\usepackage{longtable} % tableaux sur plusieurs pages
\usepackage[chapter]{algorithm}
\usepackage{algpseudocode} % algorithmic
\usepackage{auto-pst-pdf} 
\usepackage{pstricks,pst-node,pst-tree}

%%%%%%%%%% personnalisation des algos

\floatname{algorithm}{Algorithme}
% changement du style des commentaires
\renewcommand{\algorithmiccomment}[1]{// #1}
\let\mylistof\listof
\renewcommand\listof[2]{\mylistof{algorithm}{\textbf{Liste des algorithmes}}}


%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Definition des variables %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%

\newcommand{\titreDuMemoire}[1]{\newcommand{\@titreDuMemoire}{#1}}
\newcommand{\typeMemoire}[1]{\newcommand{\@typeMemoire}{#1}}
\newcommand{\etudiant}[1]{\newcommand{\@etudiant}{#1}}
\newcommand{\dateSoutenance}[1]{\newcommand{\@dateSoutenance}{#1}}
\newcommand{\promo}[1]{\newcommand{\@promo}{#1}}
\newcommand{\encadrant}[1]{\newcommand{\@encadrant}{#1}}
\newcommand{\annee}[1]{\newcommand{\@annee}{#1}}
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Le jury 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\newcommand{\juryP}[1]{\newcommand{\@juryP}{#1}}
\newcommand{\juryMembre}[1]{\newcommand{\@juryMembre}{#1}}
\newcommand{\juryR}[1]{\newcommand{\@juryR}{#1}}
\newcommand{\juryRa}[1]{\newcommand{\@juryRa}{#1}}
\newcommand{\juryE}[1]{\newcommand{\@juryE}{#1}}
\newcommand{\juryEx}[1]{\newcommand{\@juryEx}{#1}}
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Mise en page
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\geometry{tmargin=2cm,bmargin=2cm,lmargin=2cm,rmargin=2cm}
\setlength\headheight{15pt}
\renewcommand{\baselinestretch}{1.2} % espace entre les lignes
\pagestyle{headings}

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Le bloc monBloc
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

\definecolor{fondBleu}{rgb}{0.95,0.95,1}

\newenvironment{formal}{%
  \def\FrameCommand{%
    \hspace{1pt}%
    {\color{RoyalBlue}\vrule width 2pt}%
    {\color{fondBleu}\vrule width 4pt}%
    \colorbox{fondBleu}%
  }%
  \MakeFramed{\advance\hsize-\width\FrameRestore}%
  \begin{adjustwidth}{}{7pt}%
  \vspace{0pt}\vspace{0pt}%
}
{%
  \vspace{2pt}\end{adjustwidth}\endMakeFramed%
}


\newcommand{\monBloc}[1]{
\begin{formal}
\emph{{#1}}
\end{formal}
}	

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% modification de la numerotation %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% niveau de hirarchie  3
\setcounter{secnumdepth}{3}	% permet de numroter 4 niveaux
\setcounter{tocdepth}{2}	% et en affiche 2 dans la toc

% saut de page aprs le titre du chapitre
\def\chapitre#1{\chapter{#1}\newpage}
% compteur de partie sous la forme A, B, ...
\renewcommand\thepart{\Alph{part}}
% compteur de chapitre sous la forme 1), 2) ...
\renewcommand{\thechapter}{\arabic{chapter}}
% compteur de section sous la forme I, II, ...
\renewcommand{\thesection}{\Roman{section}}
% compteur de sous-section sous la forme 1), 2)...
\renewcommand{\thesubsection}{\arabic{subsection})}
% compteur de sous-sous-section sous la forme a), b)...
\renewcommand{\thesubsubsection}{\arabic{subsubsection})}
%differente pagination pour les tableaux
\renewcommand{\thetable}{\arabic{chapter}.\arabic{table}}
%différente pagination pour les figures
\renewcommand{\thefigure}{\arabic{chapter}.\arabic{figure}}


\newcommand\remerciements{\chapter*{Remerciements}\addcontentsline{toc}{chapter}{Remerciements}}
\newcommand\introduction{\chapter*{Introduction}\addcontentsline{toc}{chapter}{Introduction}}
\newcommand\conclusion{\chapter*{Conclusion}\addcontentsline{toc}{chapter}{Conclusion}}
\newcommand\resume{\chapter*{}\addcontentsline{toc}{chapter}{Résumé / Abstract}}
\newcommand\annexe{\chapter*{}\addcontentsline{toc}{chapter}{Annexes}}


\RequirePackage{fancyhdr}
\pagestyle{fancy}
\fancyhf{}
\fancyfoot[C]{\thepage}
\fancyhead[L]{\tiny \leftmark}
\fancyhead[R]{\scriptsize \rightmark}

% french and english abstract on same page
%http://www.latex-community.org/forum/viewtopic.php?f=44&t=13708

\if@titlepage
  \renewenvironment{abstract}{%
      \@beginparpenalty\@lowpenalty
      \begin{center}%
        \Huge \abstractname
        \@endparpenalty\@M
      \end{center}\fancyhf{}}%
     {
     }
\fi


\newglossarystyle{clong}{%
 \renewenvironment{theglossary}%
     {\begin{longtable}{p{.3\linewidth}p{\glsdescwidth}}}%
     {\end{longtable}}%
  \renewcommand*{\glossaryheader}{}%
  \renewcommand*{\glsgroupheading}[1]{}%
  \renewcommand*{\glossaryentryfield}[5]{%
    \glstarget{##1}{##2} & ##3\glspostdescription\space ##5\\}%
  \renewcommand*{\glossarysubentryfield}[6]{%
     & \glstarget{##2}{\strut}##4\glspostdescription\space ##6\\}%
}

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% modification de la toc          %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

\RequirePackage{tocloft}
\renewcommand{\cftchapnumwidth}{\setlength{0.7cm}}
\renewcommand{\cftsecnumwidth}{\setlength{0.7cm}}
\renewcommand{\cftsubsecnumwidth}{\setlength{0.7cm}}
\renewcommand{\cftsubsubsecnumwidth}{\setlength{0.7cm}}


%surcharge des sections
\titleformat{\section}
{\normalfont\Large\bfseries}{\thesection}{0.5em}{}[\hspace{1ex}\titlerule]

% surcharge des titres des parties
\titleclass{\part}{page}
\titleformat{\part}[display]
  {\centering\normalfont\huge\bfseries}
  {\centering\normalfont\normalsize\scshape\partname\ \centering{\thepart}}
  {2ex}
  {\titlerule\vspace{1ex}}
  [\vspace{2ex}\titlerule]

{\newpage\renewcommand{\thepage}{\arabic{page}}\setcounter{page}{1}}



% enlever le point à la fin
\renewcommand*{\glspostdescription}{}
% mettre deux points apres les titres
\renewcommand{\glsnamefont}[1]{\textbf{#1 :  }}

%% Références multiples au même footnote
%% http://www.pommegyver.be/2010/11/latex-references-multiples-au-meme-footnote/
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\newcommand{\footnoteremember}[2]{
\footnote{#2}
\newcounter{#1}
\setcounter{#1}{\value{footnote}}
}

\newcommand{\footnoterecall}[1]{
\footnotemark[\value{#1}]
}

%Page de titre
\newcommand{\pageTitre}
{
	\pagecolor{lgray}
	\begin{titlepage}
		\begin{center}
			\begin{tabular}{c}
				{\scriptsize RÉPUBLIQUE DU BÉNIN}
			\end{tabular}
		\end{center}
		\vspace{-1cm}
		\begin{flushleft}
			\hspace{-0.5cm}
			\begin{tabular}{p{4cm}}
				\includegraphics[width=4cm]{images/logoCeFri.png} \\
			\end{tabular}
			\hfill
			\begin{tabular}{p{7.5cm}}
				\begin{center}
					{\scriptsize MINISTÈRE DE L'ENSEIGNEMENT SUPÉRIEUR ET DE LA RECHERCHE SCIENTIFIQUE\\}
					\vspace{0.5cm}
					{\scriptsize UNIVERSITÉ D'ABOMEY-CALAVI (UAC)\\}
					\vspace{0.5cm}
					{\scriptsize CENTRE DE FORMATION ET DE RECHERCHE EN INFORMATIQUE (CEFRI - UAC)}
				\end{center}
			\end{tabular}
			\hfill
			\begin{tabular}{p{4cm}}
				\begin{center}
					\includegraphics[height=2cm]{images/logoUAC.png}
				\end{center}
			\end{tabular}
		\end{flushleft}
		\vfill
		\begin{center}
			{\textbf{{\scriptsize MÉMOIRE DE FIN DE FORMATION\\}}}
			\vspace{0.5cm}
			{\scriptsize POUR L'OBTENTION DU\\}
			\vspace{0.5cm}
			{\LARGE \centering \@typeMemoire \\ }
			\vspace{0.5cm}
			THEME : \\
			\vspace{0.5cm}
			{\rule{\textwidth}{0.2mm}}\vspace{3mm} \\
			{{\Huge {\bf \centering \@titreDuMemoire}}}\\
			{\rule{\textwidth}{0.2mm}}\\
			\vspace{6cm}
			{ \underline{Encadrant} : \\}
			{\@encadrant}
			\vspace{1cm}
		\end{center}
		\begin{center}
			{\textbf{Année Académique : \@annee}\\}
			\vspace{1cm}
			{\bf \@promo  ~Promotion}
		\end{center}
	\end{titlepage}
}

%Page de Jury
\newcommand{\pageJury}
{
	\pagecolor{lgray}
		\begin{titlepage}
			\begin{center}
				\begin{tabular}{c}
					{\scriptsize RÉPUBLIQUE DU BÉNIN}
				\end{tabular}
			\end{center}
			\vspace{-1cm}
			\begin{flushleft}
			\hspace{-0.5cm}
			\begin{tabular}{p{4cm}}
 				\includegraphics[width=4cm]{images/logoCeFri.png} \\
			\end{tabular}
			\hfill
			\begin{tabular}{p{7.5cm}}
				\begin{center}
					{\scriptsize MINISTÈRE DE L'ENSEIGNEMENT SUPÉRIEUR ET DE LA RECHERCHE SCIENTIFIQUE\\}
					\vspace{0.5cm}
					{\scriptsize UNIVERSITÉ D'ABOMEY-CALAVI (UAC)\\}
					\vspace{0.5cm}
					{\scriptsize CENTRE DE FORMATION ET DE RECHERCHE EN INFORMATIQUE (CEFRI - UAC)}
				\end{center}
			\end{tabular}
			\hfill
			\begin{tabular}{p{4cm}}
				\begin{center}
 					\includegraphics[height=2cm]{images/logoUAC.png}
				\end{center}
			\end{tabular}
		\end{flushleft}
		\vfill
		\begin{center}
			{\textbf{{\scriptsize MÉMOIRE DE FIN DE FORMATION\\}}}
			\vspace{0.5cm}
			{\scriptsize POUR L'OBTENTION DU\\}
			\vspace{0.5cm}
			{\LARGE \centering \@typeMemoire \\ }
			\vspace{0.5cm}
			THEME : \\
			\vspace{0.5cm}
			{\rule{\textwidth}{0.2mm}}\vspace{3mm} \\
			{{\Huge {\bf \centering \@titreDuMemoire}}}\\
			{\rule{\textwidth}{0.2mm}}\\
			\vspace{2cm}
			{ \underline{Présenté \& soutenu  par} : \\}
			{\@etudiant{}}
			\vspace{1cm}
			{\textbf{\scriptsize{\@dateSoutenance \\}}}
			\vspace{1cm}
			{\textbf{{\small Devant le jury composé de :}}} 
		\end{center}
		\begin{tabular}{p{2cm}l}
			& \@juryP \\
			& \@juryMembre
		\end{tabular}
		\\
		\begin{tabular}{p{2cm}p{2cm}l}
			& ~ & \@juryR \\
			& ~ & \@juryRa \\
			& ~ & \@juryE \\
			& ~ & \@juryEx
		\end{tabular}
		\begin{center}
			{\textbf{Année Académique : \@annee}\\}
			\vspace{1cm}
			{\bf \@promo  ~Promotion}
		\end{center}
	\end{titlepage}
}


%Générer les index
\makeindex
%Activate glossary commands
\makeglossaries
%Cacher auteur et la date
\author{}
\date{}
