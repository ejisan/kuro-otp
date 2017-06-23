name := """kuro-otp"""

organization := "com.ejisan"

version := "0.0.1-SNAPSHOTS"

scalaVersion := "2.12.2"

crossScalaVersions := Seq("2.11.11", scalaVersion.value)

scalacOptions ++= {
  Seq(
    "-target:jvm-1.8",
    "-encoding", "UTF-8",
    "-Xlint",
    "-Xfatal-warnings",
    "-Ywarn-dead-code",
    "-Ywarn-inaccessible",
    "-Ywarn-infer-any",
    "-Ywarn-nullary-override",
    "-Ywarn-nullary-unit",
    "-Ywarn-numeric-widen",
    "-Ywarn-unused-import",
    "-Ywarn-value-discard",
    "-deprecation",
    "-unchecked",
    "-feature",
    "-explaintypes"
  ) ++ (scalaVersion.value.split('.').map(_.toInt).toList match {
    case v @ 2 :: 11 :: _ =>
      Seq("-optimise")
    case v @ 2 :: major :: _ if major >= 12 =>
      Seq("-opt:l:method", "-Ywarn-extra-implicit")
    case v =>
      Nil
  })
}

scalacOptions in Compile in console := Nil

scalacOptions in Compile in doc ++= Seq(
  "-sourcepath", (baseDirectory in LocalProject("kuro-otp")).value.getAbsolutePath,
  "-doc-title", "Kuro OTP (HOTP, TOTP)",
  "-doc-footer", "Copyright (c) 2017 Ryo Ejima (ejisan), Apache License v2.0.",
  "-doc-source-url", "https://github.com/ejisan/kuro-otp€{FILE_PATH}.scala")

javacOptions ++= Seq("-source", "1.8")

testOptions in Test ++= Seq(
  Tests.Argument(TestFrameworks.ScalaTest, "-oD"),
  Tests.Argument(TestFrameworks.JUnit, "-q", "-v"))

libraryDependencies ++= Seq(
  "org.scala-lang.modules" %% "scala-java8-compat" % "0.8.0",
  "commons-codec" % "commons-codec" % "1.10",
  "junit" % "junit" % "4.12" % Test,
  "com.novocode" % "junit-interface" % "0.11" % Test,
  "org.scalatest" %% "scalatest" % "3.0.1" % Test)
